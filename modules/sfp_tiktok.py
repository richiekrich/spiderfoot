"""SpiderFoot plugin: sfp_tiktok
Author: Open‑Source Intelligence / ChatGPT helper
Description: Discover TikTok accounts and pull profile + video metadata.
Updated: 2025‑04‑27

Major changes in this revision
-----------------------------
* Extra request headers to dodge TikTok bot wall
* Optional debug dump of fetched HTML for regex tuning
* More resilient JSON extraction (SIGI_STATE, window assignments, __NEXT_DATA__, generic application/json)
* Emits ERROR event when JSON cannot be parsed so the scan is no longer silent
* Gracefully skips video extraction when `max_videos == 0`
"""

import html
import json
import re
import time
from pathlib import Path
from spiderfoot import SpiderFootPlugin, SpiderFootEvent


class sfp_tiktok(SpiderFootPlugin):

    ##########################
    #  Plugin metadata
    ##########################

    meta = {
        "name": "TikTok OSINT",
        "summary": "Discovers TikTok accounts and extracts profile/video metadata using multiple verification methods.",
        "flags": ["slow", "errorprone", "social-media"],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Social Media"],
        "dataSource": {
            "website": "https://www.tiktok.com/",
            "model": "FREE_NOAUTH_UNLIMITED",
            "favIcon": "https://www.tiktok.com/favicon.ico",
            "logo": "https://www.tiktok.com/favicon.ico",
            "description": "TikTok is a social media platform for short‑form mobile videos."
        },
    }

    ##########################
    #  Options
    ##########################

    opts = {
        "fetch_videos": True,
        "verify_account": True,
        "parse_email_local": True,
        "fetch_profile_details": True,
        "delay": 1,
        "max_videos": 10,
        "useragent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36"
        ),
        "parse_bio": True,
        "_debug": False,          # write fetched HTML + verbose logs
        "_debug_dir": "./data/debug/tiktok"  # where to dump html
    }

    optdescs = {
        "fetch_videos": "Retrieve recent video URLs and metadata",
        "verify_account": "Validate account existence through JSON metadata",
        "parse_email_local": "Parse email local parts as potential usernames",
        "fetch_profile_details": "Extract profile details (bio, stats, etc.)",
        "delay": "Delay between requests in seconds",
        "max_videos": "Maximum number of videos to retrieve per account (0 = skip)",
        "useragent": "Custom User‑Agent string for requests",
        "parse_bio": "Extract emails and domains from profile bios",
        "_debug": "Enable verbose logging and HTML dumps",
        "_debug_dir": "Directory to dump HTML when _debug = True",
    }

    ##########################
    #  Boilerplate
    ##########################

    def setup(self, sfc, user_opts: dict = {}):
        self.sf = sfc
        self.__data_seen = set()
        self.opts.update(user_opts)
        # ensure debug dir exists
        if self.opts.get("_debug"):
            Path(self.opts.get("_debug_dir")).mkdir(parents=True, exist_ok=True)
        # baseline headers
                # baseline headers (ASCII-only keys!)
        self._base_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",  # NOTE: plain ASCII hyphen
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "User-Agent": self.opts.get("useragent"),
        }

    def watchedEvents(self):
        return ["USERNAME", "SOCIAL_MEDIA", "EMAILADDR"]

    def producedEvents(self):
        return [
            "SOCIAL_MEDIA", "LINKED_URL", "RAW_RIR_DATA",
            "ACCOUNT_EXTERNAL_OWNER", "PROFILE_PHOTO", "GEOINFO",
            "DESCRIPTION", "INFO", "ERROR", "TIKTOK_PROFILE_INFO",
            "EMAILADDR", "DOMAIN_NAME",
        ]

    ##########################
    #  Core handlers
    ##########################

    def handleEvent(self, event):
        etype, edata = event.eventType, event.data
        self.debug(f"Received {etype}: {edata}")

        if self.seen(edata):
            return
        self.markAsSeen(edata)

        if etype == "EMAILADDR" and self.opts["parse_email_local"]:
            uname = edata.split("@")[0]
            if self._valid_username(uname):
                self._process_username(uname, event)
        elif etype in ("USERNAME", "SOCIAL_MEDIA") and self._valid_username(edata):
            self._process_username(edata.lower(), event)

    def _valid_username(self, username: str) -> bool:
        ok = bool(re.match(r"^[\w.-]{3,32}$", username))
        if not ok:
            self.debug(f"Invalid TikTok username: {username}")
        return ok

    ##########################
    #  Username pipeline
    ##########################

    def _process_username(self, username: str, parent_event):
        time.sleep(self.opts["delay"])
        url = f"https://www.tiktok.com/@{username}"
        res = self.sf.fetchUrl(url, headers=self._base_headers, timeout=15, verify=False)

        if not res or not res.get("content"):
            self.debug(f"Empty response for {url}")
            return

        html_text = res.get("content", "")
        code = res.get("code")
        self.debug(f"HTTP {code} for {url} (len={len(html_text)})")

        # Debug dump
        if self.opts.get("_debug"):
            dump = Path(self.opts["_debug_dir"]) / f"{username}.html"
            dump.write_text(html_text, encoding="utf-8", errors="ignore")
            self.debug(f"Dumped fetched HTML to {dump}")

        if code == 404:
            self.debug("404 page returned")
            return

        extracted = self._extract_json(html_text)
        if not extracted:
            self._emit_error("Unable to extract TikTok JSON", parent_event)
            return

        data, raw_json = extracted["data"], extracted["raw"]
        if raw_json:
            self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", raw_json, self.__class__.__name__, parent_event))

        if not self.opts["verify_account"] or self._verify_account(data, username):
            self.emitSocialMedia(url, parent_event)
            self.notifyListeners(SpiderFootEvent("INFO", f"TikTok account detected: {username}", self.__class__.__name__, parent_event))
            if self.opts["fetch_profile_details"]:
                self._process_profile(data, parent_event)

    ##########################
    #  Extraction / verification helpers
    ##########################

    _SIGI_PAT = re.compile(r'<script[^>]*id="?SIGI_STATE"?[^>]*>(.*?)</script>', re.S)
    _SIGI_WIN = re.compile(r'window\["SIGI_STATE"\]\s*=\s*({.*?});', re.S)
    _NEXT_PAT = re.compile(r'<script[^>]*id="?__NEXT_DATA__"?[^>]*>(.*?)</script>', re.S)
    _NEXT_WIN = re.compile(r'window\["__NEXT_DATA__"\]\s*=\s*({.*?});', re.S)
    _APPJSON = re.compile(r'<script[^>]*application/json[^>]*>(\{.*?"UserModule".*?\})</script>', re.S)

    def _extract_json(self, html_src: str):
        # try in order of likelihood
        for rgx, typ in (
            (self._SIGI_PAT, "sigi"),
            (self._SIGI_WIN, "sigi"),
            (self._NEXT_PAT, "next"),
            (self._NEXT_WIN, "next"),
            (self._APPJSON, "json"),
        ):
            m = rgx.search(html_src)
            if not m:
                continue
            json_str = html.unescape(m.group(1))  # handle &quot;
            try:
                parsed = json.loads(json_str)
            except Exception as e:
                self.error(f"JSON parse error ({typ}): {e}")
                continue
            if typ == "next":
                props = parsed.get("props", {}).get("pageProps", {})
                user_info = props.get("userInfo", {}).get("user", {})
                items = props.get("itemInfo", {}).get("itemStruct", {})
                parsed = {
                    "UserModule": {"users": {user_info.get("uniqueId", ""): user_info}},
                    "ItemModule": items or {},
                }
            return {"data": parsed, "raw": json_str}
        return None

    def _verify_account(self, data: dict, username: str) -> bool:
        users = data.get("UserModule", {}).get("users") or data.get("ShareUser", {}).get("users")
        if not users:
            self.debug("No UserModule in JSON")
            return False
        info = next((u for u in users.values() if u.get("uniqueId", "").lower() == username), None)
        if not info:
            self.debug("uniqueId not found in users")
            return False
        if info.get("isPrivate"):
            self.debug("Account is private")
        if info.get("isBan", False) or info.get("status", 0) != 0:
            self.debug("Account banned/disabled")
        return True

    ##########################
    #  Emitters
    ##########################

    def _process_profile(self, data, parent_event):
        # Profile details
        for user in data.get("UserModule", {}).get("users", {}).values():
            if url := user.get("avatarThumb"):
                self.notifyListeners(SpiderFootEvent("PROFILE_PHOTO", url, self.__class__.__name__, parent_event))
            if bio := user.get("signature"):
                self.notifyListeners(SpiderFootEvent("DESCRIPTION", bio, self.__class__.__name__, parent_event))
                if self.opts["parse_bio"]:
                    self._parse_bio_entities(bio, parent_event)
            if region := user.get("region"):
                self.notifyListeners(SpiderFootEvent("GEOINFO", region, self.__class__.__name__, parent_event))
            if nick := user.get("nickname"):
                self.notifyListeners(SpiderFootEvent("ACCOUNT_EXTERNAL_OWNER", nick, self.__class__.__name__, parent_event))
            profile_info = {
                "nickname": user.get("nickname"),
                "followers": user.get("followerCount"),
                "likes": user.get("heartCount"),
                "videos": user.get("videoCount"),
                "private": user.get("isPrivate", False),
                "verified": user.get("verified", False),
            }
            self.notifyListeners(SpiderFootEvent("TIKTOK_PROFILE_INFO", json.dumps(profile_info), self.__class__.__name__, parent_event))

        # Videos
        if not self.opts["fetch_videos"] or self.opts["max_videos"] == 0:
            return
        count = 0
        for vid_id, vid in data.get("ItemModule", {}).items():
            url = f"https://www.tiktok.com/@{vid.get('author')}/video/{vid_id}"
            self.notifyListeners(SpiderFootEvent("LINKED_URL", url, self.__class__.__name__, parent_event))
            if desc := vid.get("desc"):
                self.notifyListeners(SpiderFootEvent("DESCRIPTION", desc, self.__class__.__name__, parent_event))
            count += 1
            if count >= self.opts["max_videos"]:
                break

    ##########################
    #  Helpers
    ##########################

    EMAIL_RE = re.compile(r"\b[\w.+%-]+@[\w.-]+\.[A-Za-z]{2,}\b")
    DOMAIN_RE = re.compile(r"\b(?:https?://)?(?:www\.)?([\w-]+\.[A-Za-z]{2,})(?:/|\b)")

    def _parse_bio_entities(self, bio: str, parent_event):
        for mail in set(self.EMAIL_RE.findall(bio)):
            self.notifyListeners(SpiderFootEvent("EMAILADDR", mail, self.__class__.__name__, parent_event))
        for dom in set(self.DOMAIN_RE.findall(bio)):
            self.notifyListeners(SpiderFootEvent("DOMAIN_NAME", dom, self.__class__.__name__, parent_event))

    ##########################
    #  Seen cache helpers
    ##########################

    def seen(self, item):
        return item in self.__data_seen

    def markAsSeen(self, item):
        self.__data_seen.add(item)

    ##########################
    #  Utility
    ##########################

    def _emit_error(self, msg, parent_event):
        self.notifyListeners(SpiderFootEvent("ERROR", msg, self.__class__.__name__, parent_event))
