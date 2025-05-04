# test/unit/modules/test_bluesky_core.py
import json
import pytest
from modules.sfp_bluesky import sfp_bluesky
from spiderfoot import SpiderFootEvent           # <- import the event class

def test_process_handle_with_mock():
    # 1) Fake profile JSON
    fake_profile = {
        "avatar": "https://img.png",
        "displayName": "T",
        "description": "Bio",
        "followersCount": 1,
        "followsCount": 2,
        "postsCount": 0,
        "handle": "t.example",
        "did": "did:plc:x"
    }
    mock_res = {"code": 200, "content": json.dumps(fake_profile)}

    # 2) Instantiate plugin, set up with dummy controller
    plugin = sfp_bluesky()
    class DummySF: pass
    dummy_sf = DummySF()
    plugin.setup(dummy_sf, {"delay": 0, "fetch_posts": False})

    # 3) Stub fetchUrl
    dummy_sf.fetchUrl = lambda *args, **kwargs: mock_res

    # 4) Build a minimal ROOT parent event
    parent_evt = SpiderFootEvent("ROOT", "root", "test", None)

    # 5) Capture emitted events
    collected = []
    plugin.notifyListeners = lambda e: collected.append(e)

    # 6) Invoke pipeline
    plugin._process_handle("t.example", parent_evt=parent_evt)

    # 7) Validate output
    types = {e.eventType for e in collected}
    assert "SOCIAL_MEDIA"         in types
    assert "PROFILE_PHOTO"        in types
    assert "BLUESKY_PROFILE_INFO" in types

def test_parse_bio_and_posts():
    # Fake profile with bio + 2 posts
    prof = {
        "avatar": "x", "displayName": "x",
        "description": "find me at mail@test.com https://example.com",
        "followersCount": 0, "followsCount": 0, "postsCount": 2,
        "handle": "t.example", "did": "did:plc:x"
    }
    feed = {
        "feed": [
            {"post": {"uri": "at://t.example/1",
                      "record": {"text": "hello"}}},
            {"post": {"uri": "at://t.example/2",
                      "record": {"text": "world"}}}
        ]
    }
    plugin = sfp_bluesky()
    class DummySF: pass
    sf = DummySF()
    plugin.setup(sf, {"delay": 0, "fetch_posts": True, "max_posts": 2})

    # stub first call (profile) then second call (feed)
    sf.fetchUrl = lambda url, **k: (
        {"code": 200, "content": json.dumps(prof)}
        if "getProfile" in url else
        {"code": 200, "content": json.dumps(feed)}
    )

    parent = SpiderFootEvent("ROOT", "root", "test", None)
    out = []
    plugin.notifyListeners = lambda e: out.append(e)
    plugin._process_handle("t.example", parent)

    types = {e.eventType for e in out}
    assert {"EMAILADDR","DOMAIN_NAME","LINKED_URL"}.issubset(types)
    assert sum(1 for e in out if e.eventType=="LINKED_URL") == 2
