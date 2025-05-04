import pytest
from modules.sfp_bluesky import sfp_bluesky

@pytest.mark.parametrize("inp,expected", [
    ("osintpublic.bsky.social", "osintpublic.bsky.social"),
    ("@John-Doe.example",        "john-doe.example"),
    ("invalid_handle!",          None),
])
def test_valid_handle(inp, expected):
    # Instantiate with no args
    plugin = sfp_bluesky()
    # (Optionally: plugin.setup(None) if your helper uses `self.sf`)
    result = plugin._valid_handle(inp)
    assert result == expected
