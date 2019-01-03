# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

import requests

from cuckoo.misc import cwd

domains = set()
ips = set()
urls = set()


def get_whitelist_api_url(indicator_type):
    from cuckoo.common.config import config

    url = config("processing:whitelist:url")
    endpoint = config("processing:whitelist:{}_endpoint".format(indicator_type))

    return url.rstrip('/') + '/' + endpoint.lstrip('/')


def get_whitelist_api_headers():
    from cuckoo.common.config import config

    token = config("processing:whitelist:token")
    return {'Authorization': 'Token {}'.format(token)}


def is_whitelisted_domain(domain):
    from cuckoo.common.config import config

    # Initialize the domain whitelist.
    if not domains:
        for line in open(cwd("whitelist", "domain.txt", private=True), "rb"):
            if not line.strip() or line.startswith("#"):
                continue
            domains.add(line.strip())

        # Collect whitelist also from $CWD if available.
        if os.path.exists(cwd("whitelist", "domain.txt")):
            for line in open(cwd("whitelist", "domain.txt"), "rb"):
                if not line.strip() or line.startswith("#"):
                    continue
                domains.add(line.strip())

        if config("processing:whitelist:enabled"):
            api_url = get_whitelist_api_url("domain")
            headers = get_whitelist_api_headers()

            r = requests.get(api_url, headers=headers)
            for d in r.json():
                domains.add(d)

    return domain in domains


def is_whitelisted_ip(ip):
    from cuckoo.common.config import config

    if not ips:
        if config("processing:whitelist:enabled"):
            api_url = get_whitelist_api_url("ip")
            headers = get_whitelist_api_headers()

            r = requests.get(api_url, headers=headers)
            for ip in r.json():
                ips.add(ip)

    return ip in ips


def is_whitelisted_url(url):
    from cuckoo.common.config import config

    url = url.lower().strip()

    if not urls:
        if config("processing:whitelist:enabled"):
            api_url = get_whitelist_api_url("api_url")
            headers = get_whitelist_api_headers()

            r = requests.get(api_url, headers=headers)
            for u in r.json():
                urls.add(u)

    return url in urls
