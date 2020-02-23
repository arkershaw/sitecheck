#!/usr/bin/env python3
# -*- coding: utf-8 -*-

if __name__ == '__main__':
    from sitecheck.core import VERSION
    from sitecheck.modules import InboundLinks
    import json

    settings = {
        'Version': VERSION,
        'DownloadURL': 'https://github.com/arkershaw/sitecheck/releases'
    }

    inbound = InboundLinks()

    with open('settings.js', 'w') as f:
        json.dump(settings, f, indent=2)

    with open('search-engines.js', 'w') as f:
        json.dump(inbound.engine_parameters, f, indent=2)
