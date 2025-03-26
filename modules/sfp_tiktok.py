import re
import json
import time
from spiderfoot import SpiderFootPlugin, SpiderFootEvent

class sfp_tiktok(SpiderFootPlugin):

    meta = {
        'name': "TikTok OSINT",
        'summary': "Discovers TikTok accounts and extracts profile/video metadata using multiple verification methods.",
        'flags': ["slow", "errorprone", "social-media"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Social Media"],
        'dataSource': {
            'website': "https://www.tiktok.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [],
            'favIcon': "https://www.tiktok.com/favicon.ico",
            'logo': "https://www.tiktok.com/favicon.ico",
            'description': "TikTok is a social media platform for short-form mobile videos."
        }
    }

    opts = {
        "fetch_videos": True,
        "verify_account": True,
        "parse_email_local": True,
        "fetch_profile_details": True,
        "delay": 1,
        "max_videos": 10,
        "useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    optdescs = {
        "fetch_videos": "Retrieve recent video URLs and metadata",
        "verify_account": "Validate account existence through JSON metadata",
        "parse_email_local": "Parse email local parts as potential usernames",
        "fetch_profile_details": "Extract profile details (bio, stats, etc.)",
        "delay": "Delay between requests in seconds",
        "max_videos": "Maximum number of videos to retrieve per account",
        "useragent": "Custom User-Agent string for requests"
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSeen = set()
        self.__tempEventData = None
        self.opts.update(userOpts)

    def watchedEvents(self):
        return ["USERNAME", "SOCIAL_MEDIA", "EMAILADDR"]

    def producedEvents(self):
        return ["SOCIAL_MEDIA", "LINKED_URL", "RAW_RIR_DATA", 
                "ACCOUNT_EXTERNAL_OWNER", "PROFILE_PHOTO", 
                "GEOINFO", "DESCRIPTION"]

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data
        self.__tempEventData = None

        if self.seen(eventData):
            return
        self.markAsSeen(eventData)

        if eventName == "EMAILADDR" and self.opts["parse_email_local"]:
            local_part = eventData.split('@')[0].strip()
            if self.validateUsername(local_part):
                self.processUsername(local_part, event)

        elif eventName in ["USERNAME", "SOCIAL_MEDIA"]:
            if self.validateUsername(eventData):
                self.processUsername(eventData.lower(), event)

    def validateUsername(self, username):
        if not re.match(r"^[a-zA-Z0-9_.]{3,24}$", username):
            self.debug(f"Invalid TikTok username format: {username}")
            return False
        return True

    def processUsername(self, username, parentEvent):
        time.sleep(self.opts["delay"])
        url = f"https://www.tiktok.com/@{username}"
        self.__tempEventData = url

        res = self.sf.fetchUrl(
            url,
            useragent=self.opts["useragent"],
            timeout=15,
            verify=False  # Only keep valid parameters
        )

        if res['code'] == 404 or "Couldn't find this account" in res.get('content', ''):
            return

        if not self.opts["verify_account"] or self.verifyAccount(res['content'], username):
            self.emitSocialMedia(url, parentEvent)
            self.processProfileData(res['content'], username, parentEvent)

    def verifyAccount(self, content, username):
        try:
            user_data = self.extractUserData(content)
            if not user_data:
                return False
                
            users = user_data.get('UserModule', {}).get('users', {})
            return username.lower() in [u.lower() for u in users.keys()]
        except Exception as e:
            self.error(f"Account verification failed: {e}")
            return False

    def emitSocialMedia(self, url, parentEvent):
        evt = SpiderFootEvent("SOCIAL_MEDIA", f"TikTok Account: {url}", 
                            self.__name__, parentEvent)
        self.notifyListeners(evt)

    def processProfileData(self, content, username, parentEvent):
        user_data = self.extractUserData(content)
        if not user_data:
            return

        self.emitRawData(user_data, username, parentEvent)
        
        if self.opts["fetch_profile_details"]:
            self.extractProfileDetails(user_data, parentEvent)
            
        if self.opts["fetch_videos"]:
            self.extractVideoData(user_data, parentEvent)

    def extractUserData(self, content):
        try:
            sigi_data = re.search(
                r'<script id="SIGI_STATE"[^>]*>([^<]+)</script>', 
                content
            )
            return json.loads(sigi_data.group(1)) if sigi_data else None
        except Exception as e:
            self.error(f"Error parsing user data: {e}")
            return None

    def emitRawData(self, data, username, parentEvent):
        evt = SpiderFootEvent("RAW_RIR_DATA", 
                            json.dumps({
                                'source': 'TikTok',
                                'username': username,
                                'data': data
                            }), 
                            self.__name__, parentEvent)
        self.notifyListeners(evt)

    def extractProfileDetails(self, user_data, parentEvent):
        try:
            users = user_data.get('UserModule', {}).get('users', {})
            for user_id, details in users.items():
                # Profile Photo
                if details.get('avatarThumb'):
                    evt = SpiderFootEvent("PROFILE_PHOTO", details['avatarThumb'],
                                        self.__name__, parentEvent)
                    self.notifyListeners(evt)
                
                # Bio/Description
                if details.get('signature'):
                    evt = SpiderFootEvent("DESCRIPTION", details['signature'],
                                        self.__name__, parentEvent)
                    self.notifyListeners(evt)
                
                # Geographical Info
                if details.get('region'):
                    evt = SpiderFootEvent("GEOINFO", details['region'],
                                        self.__name__, parentEvent)
                    self.notifyListeners(evt)
        except Exception as e:
            self.error(f"Error extracting profile details: {e}")

    def extractVideoData(self, user_data, parentEvent):
        try:
            video_list = user_data.get('ItemModule', {})
            count = 0
            
            for video_id, video_data in video_list.items():
                if count >= self.opts["max_videos"]:
                    break
                
                video_url = f"https://www.tiktok.com/@{video_data.get('author')}/video/{video_id}"
                evt = SpiderFootEvent("LINKED_URL", video_url,
                                    self.__name__, parentEvent)
                self.notifyListeners(evt)
                
                # Optional: Emit video description
                if video_data.get('desc'):
                    evt = SpiderFootEvent("DESCRIPTION", video_data['desc'],
                                        self.__name__, parentEvent)
                    self.notifyListeners(evt)
                
                count += 1
        except Exception as e:
            self.error(f"Error extracting video data: {e}")

    def seen(self, item):
        return item in self.__dataSeen

    def markAsSeen(self, item):
        self.__dataSeen.add(item)
        