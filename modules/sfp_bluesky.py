# SpiderFoot plug-in: sfp_bluesky
#
# Updated: 2025-04-28 (Rev-2: fix emitSocialMedia + stricter handle regex)

import json
import re
import time
from spiderfoot import SpiderFootPlugin, SpiderFootEvent


class sfp_bluesky(SpiderFootPlugin):

    meta = {
        "name": "Bluesky / AT-proto OSINT",
        "summary": "Discovers Bluesky accounts and extracts profile / post metadata.",
        "flags": ["slow", "social-media"],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Social Media"],
        "dataSource": {
            "website": "https://bsky.app/",
            "model": "FREE_NOAUTH_UNLIMITED",
            "favIcon": "https://bsky.app/apple-touch-icon.png",
            "logo": "https://bsky.app/apple-touch-icon.png",
            "description": "Bluesky is a decentralised social network built on the AT Protocol."
        },
    }

    opts = {
        "fetch_posts": True,
        "max_posts": 20,
        "delay": 1,
        "useragent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36"
        ),
        "parse_bio": True,
        "parse_email_local": True,
    }

    optdescs = {
        "fetch_posts": "Retrieve recent posts for each account",
        "max_posts": "Maximum number of posts to retrieve (0 = skip)",
        "delay": "Delay between requests in seconds",
        "useragent": "Custom User-Agent header",
        "parse_bio": "Extract domains / e-mails from profile descriptions",
        "parse_email_local": "Treat e-mail local parts as potential handles",
    }

    # ------------------------------------------------------------------ #

    def setup(self, sfc, user_opts: dict = {}):
        self.sf = sfc
        self.__seen = set()
        self.opts.update(user_opts)
        self._hdr = {
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": self.opts["useragent"],
        }

    def watchedEvents(self):
        return [
            "USERNAME",       # not actually triggered for @handles
            "SOCIAL_MEDIA",   # URLs like https://bsky.app/profile/…
            "EMAILADDR",
            "DOMAIN_NAME",    # osintpublic.bsky.social
            "INTERNET_NAME",  # @osintpublic.bsky.social
        ]


    def producedEvents(self):
        return [
            "SOCIAL_MEDIA", "LINKED_URL", "PROFILE_PHOTO", "DESCRIPTION",
            "ACCOUNT_EXTERNAL_OWNER", "INFO", "ERROR", "GEOINFO",
            "BLUESKY_PROFILE_INFO", "EMAILADDR", "DOMAIN_NAME",
        ]

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    # stricter: must start with alnum, may contain '.', '-' afterwards
    _HANDLE_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$")
    _EMAIL_RE = re.compile(r"\b[\w.+%-]+@[\w.-]+\.[A-Za-z]{2,}\b")
    _DOMAIN_RE = re.compile(r"\b(?:https?://)?(?:www\.)?([\w-]+\.[A-Za-z]{2,})(?:/|\b)")

    def _valid_handle(self, h: str):
        h = h.lower().strip()
        if h.startswith("@"):
            h = h[1:]
        return h if self._HANDLE_RE.match(h) else None

    def _emit_social(self, url: str, parent_evt: SpiderFootEvent):
        """Compat shim for older SpiderFoot versions lacking emitSocialMedia()."""
        self.notifyListeners(
            SpiderFootEvent("SOCIAL_MEDIA", url, self.__class__.__name__, parent_evt)
        )

    # ------------------------------------------------------------------ #

    def _mark(self, item): self.__seen.add(item)
    def _seen(self, item): return item in self.__seen

    # ------------------------------------------------------------------ #
    #  Event router
    # ------------------------------------------------------------------ #
    def handleEvent(self, evt: SpiderFootEvent):
        etype, edata = evt.eventType, evt.data
        self.debug(f"Got {etype}: {edata}")

        if self._seen(edata):
            return
        self._mark(edata)

        if etype == "EMAILADDR" and self.opts["parse_email_local"]:
            cand = edata.split("@")[0] + ".bsky.social"
            if self._valid_handle(cand):
                self._process_handle(cand, evt)

        elif etype in (
        "USERNAME",
        "SOCIAL_MEDIA",
        "DOMAIN_NAME",
        "INTERNET_NAME"   # now handled
        ) and self._valid_handle(edata.lstrip("@")):
            self._process_handle(edata.lstrip("@"), evt)     # ← correct variable


    # ------------------------------------------------------------------ #
    #  Core pipeline
    # ------------------------------------------------------------------ #
    _API = "https://public.api.bsky.app/xrpc"

    def _process_handle(self, handle: str, parent_evt):
        time.sleep(self.opts["delay"])
        prof = f"{self._API}/app.bsky.actor.getProfile?actor={handle}"
        res = self.sf.fetchUrl(prof, headers=self._hdr, timeout=15, verify=True)

        if not res or not res.get("content"):
            self.debug(f"Empty profile response for {handle}")
            return
        if res.get("code") == 400:
            self.debug(f"Handle {handle} not found")
            return

        try:
            data = json.loads(res["content"])
        except Exception as e:
            self._emit_error(f"JSON parse error: {e}", parent_evt)
            return

        acct_url = f"https://bsky.app/profile/{handle}"
        self._emit_social(acct_url, parent_evt)
        self.notifyListeners(SpiderFootEvent(
            "INFO", f"Bluesky account detected: {handle}",
            self.__class__.__name__, parent_evt
        ))

        self._process_profile(data, parent_evt)

        if self.opts["fetch_posts"] and self.opts["max_posts"] > 0:
            self._process_posts(handle, parent_evt)

    # ------------------------------------------------------------------ #
    #  Profile / posts
    # ------------------------------------------------------------------ #
    def _process_profile(self, data: dict, parent_evt):
        if (avatar := data.get("avatar")):
            self.notifyListeners(SpiderFootEvent(
                "PROFILE_PHOTO", avatar, self.__class__.__name__, parent_evt
            ))
        if (name := data.get("displayName")):
            self.notifyListeners(SpiderFootEvent(
                "ACCOUNT_EXTERNAL_OWNER", name, self.__class__.__name__, parent_evt
            ))
        if (desc := data.get("description")):
            self.notifyListeners(SpiderFootEvent(
                "DESCRIPTION", desc, self.__class__.__name__, parent_evt
            ))
            if self.opts["parse_bio"]:
                self._parse_bio(desc, parent_evt)

        stats = {
            "followers": data.get("followersCount"),
            "following": data.get("followsCount"),
            "posts": data.get("postsCount"),
            "handle": data.get("handle"),
            "did": data.get("did"),
        }
        self.notifyListeners(SpiderFootEvent(
            "BLUESKY_PROFILE_INFO", json.dumps(stats),
            self.__class__.__name__, parent_evt
        ))

    def _process_posts(self, handle: str, parent_evt):
        feed = (
            f"{self._API}/app.bsky.feed.getAuthorFeed?"
            f"actor={handle}&limit={self.opts['max_posts']}"
        )
        time.sleep(self.opts["delay"])
        res = self.sf.fetchUrl(feed, headers=self._hdr, timeout=15, verify=True)
        if not res or not res.get("content"):
            return
        try:
            data = json.loads(res["content"])
        except Exception as e:
            self._emit_error(f"Feed JSON parse error: {e}", parent_evt)
            return

        for itm in data.get("feed", []):
            post = itm.get("post", {})
            uri = post.get("uri")
            if not uri:
                continue
            url = f"https://bsky.app/profile/{handle}/post/{uri.split('/')[-1]}"
            self.notifyListeners(SpiderFootEvent(
                "LINKED_URL", url, self.__class__.__name__, parent_evt
            ))
            if (text := post.get("record", {}).get("text")):
                self.notifyListeners(SpiderFootEvent(
                    "DESCRIPTION", text, self.__class__.__name__, parent_evt
                ))

    # ------------------------------------------------------------------ #
    #  Misc helpers
    # ------------------------------------------------------------------ #
    def _parse_bio(self, bio: str, parent_evt):
        for mail in set(self._EMAIL_RE.findall(bio)):
            self.notifyListeners(SpiderFootEvent(
                "EMAILADDR", mail, self.__class__.__name__, parent_evt
            ))
        for dom in set(self._DOMAIN_RE.findall(bio)):
            self.notifyListeners(SpiderFootEvent(
                "DOMAIN_NAME", dom, self.__class__.__name__, parent_evt
            ))

    def _emit_error(self, msg, parent_evt):
        self.notifyListeners(SpiderFootEvent(
            "ERROR", msg, self.__class__.__name__, parent_evt
        ))
