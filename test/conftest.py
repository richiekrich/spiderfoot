import pytest
from spiderfoot import SpiderFootHelpers

@pytest.fixture(autouse=True)
def default_options(request):
    # Only apply defaults when running tests in a test class
    if request.cls is None:
        return

    # Core SpiderFoot options
    request.cls.default_options = {
        '_debug': False,
        '__logging': True,            # Logging in general
        '__outputfilter': None,       # Event types to filter from modules' output
        '_useragent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; '
            'rv:62.0) Gecko/20100101 Firefox/62.0'
        ),
        '_dnsserver': '',             # Override the default resolver
        '_fetchtimeout': 5,           # Seconds before giving up on a fetch
        '_internettlds': (
            'https://publicsuffix.org/list/effective_tld_names.dat'
        ),
        '_internettlds_cache': 72,
        '_genericusers': ",".join(
            SpiderFootHelpers.usernamesFromWordlists(['generic-usernames'])
        ),
        '__database': (
            f"{SpiderFootHelpers.dataPath()}/spiderfoot.test.db"
        ),                            # Test database file
        '__modules__': None,          # Will be set after start-up
        '__correlationrules__': None, # Will be set after start-up
        '_socks1type': '',
        '_socks2addr': '',
        '_socks3port': '',
        '_socks4user': '',
        '_socks5pwd': '',
        '__logstdout': False
    }

    # Web interface defaults
    request.cls.web_default_options = {
        'root': '/'
    }

    # CLI interface defaults
    request.cls.cli_default_options = {
        "cli.debug": False,
        "cli.silent": False,
        "cli.color": True,
        "cli.output": "pretty",
        "cli.history": True,
        "cli.history_file": "",
        "cli.spool": False,
        "cli.spool_file": "",
        "cli.ssl_verify": True,
        "cli.username": "",
        "cli.password": "",
        "cli.server_baseurl": "http://127.0.0.1:5001"
    }
