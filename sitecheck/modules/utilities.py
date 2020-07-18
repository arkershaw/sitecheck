# -*- coding: utf-8 -*-

# Copyright 2009-2020 Andrew Kershaw

# This file is part of sitecheck.

# Sitecheck is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Sitecheck is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with sitecheck. If not, see <http://www.gnu.org/licenses/>.

import re
import urllib.parse
import urllib.request
from io import StringIO
import json
from domaincheck import Host, domain_report, get_host, find_soa
from sitecheck.reporting import requires_report
from sitecheck.core import ModuleBase


class InboundLinks(ModuleBase):
    def __init__(self, engines=None):
        super(InboundLinks, self).__init__()
        self.domain = ''
        self.link = None
        self.engines = engines
        # URL, page regex, page size, initial offset
        self.engine_parameters = {
            'Google': [
                'http://www.google.co.uk/search?num=100&q=site:{domain}&start={index}&as_qdr=all',
                '(?:About )?([0-9,]+) results',
                100, 0
            ],
            'Bing': [
                'http://www.bing.com/search?q=site:{domain}&first={index}',
                '[0-9,]+-[0-9,]+ of ([0-9,]+) results',
                10, 1
            ]
        }
        self.inbound = set()

    @requires_report
    def begin(self, report):
        if hasattr(self.sitecheck.session, 'check_for_updates') and self.sitecheck.session.check_for_updates:
            try:
                settings = urllib.request.urlopen('http://www.site-check.co.uk/search-engines.js')\
                    .read().decode('utf-8')
                ss = StringIO(settings)
                sd = json.load(ss)
            except:
                report.add_warning('Update check failed - please notify: andy@site-check.co.uk')
            else:
                self.engine_parameters = sd

        for k in self.engine_parameters:
            self.engine_parameters[k][1] = re.compile(self.engine_parameters[k][1], re.IGNORECASE)

        self.domain = urllib.parse.urlparse(self.sitecheck.session.domain).netloc

        dp = self.sitecheck.session.domain[self.sitecheck.session.domain.find(self.domain):]
        self.link = re.compile('"(https?://{0}[^"]*)"'.format(re.escape(dp), re.IGNORECASE))

        if not self.engines:
            self.engines = list(self.engine_parameters.keys())
        for ei in range(len(self.engines)):
            se = self.engines[ei]
            if se in self.engine_parameters:
                e = self.engine_parameters[se]
                e.extend([0, e[3]]) # Total results, current result offset
                url = e[0].format(domain=self.domain, index=e[3])
                req = self._create_request(url, se)
                req.modules = [self]
                req.verb = 'GET'  # Otherwise it will be set to HEAD as it is on another domain
                self.sitecheck.request_queue.put(req)
            else:
                report.add_error('Unknown search engine: [{0}]'.format(se))
                self.engines.pop(ei)

    def process(self, request, response, report):
        if request.source == self.name and response.is_html and request.referrer in self.engine_parameters:
            with self.sync_lock:
                e = self.engine_parameters[request.referrer]
                match = re.search(e[1], response.content)
                if match:
                    e[4] = int(re.sub('[^0-9]', '', match.groups()[0]))

                    for m in self.link.finditer(response.content):
                        url = m.groups()[0]
                        self.inbound.add(url)
                        self._add_request(url, str(request))

                    e[5] += e[2]
                    if e[5] < e[4]:
                        url = e[0].format(domain=self.domain, index=e[5])
                        req = self._create_request(url, request.referrer)
                        req.modules = [self]
                        req.verb = 'GET'  # Otherwise it will be set to HEAD as it is on another domain
                        self.sitecheck.request_queue.put(req)

    @requires_report
    def complete(self, report):
        urls = list(self.inbound)
        if len(urls) > 0:
            urls.sort()
            for u in urls:
                report.add_message(u)
            report.add_message('Total: {0}'.format(len(self.inbound)))
        else:
            report.add_message('No inbound links found')


class DomainCheck(ModuleBase):
    def __init__(self, domains=None, relay=False):
        super(DomainCheck, self).__init__()
        if domains and len(domains) > 0:
            hosts = [get_host(d) for d in set(domains)]
            self.domains = dict([(d, False) for d in hosts])
            self.main_domain = domains[0]
            self.root_domain = self.main_domain
        else:
            self.domains = {}
            self.main_domain = ''
            self.root_domain = ''

        self.relay = relay

    def begin(self):
        # Issue a request for each additional domain.
        for domain in self.domains:
            url = 'http://{0}'.format(domain)
            req = self._create_request(url, url)
            req.modules = [self]
            self.sitecheck.request_queue.put(req)

        # Add the main domain. It will already have a request.
        self.main_domain = get_host(self.sitecheck.session.domain)
        self.root_domain = find_soa(self.main_domain)
        self.domains[self.main_domain] = False

    def process(self, request, response, report):
        check = False
        with self.sync_lock:
            if request.domain in self.domains and not self.domains[request.domain]:
                self.domains[request.domain] = True
                check = True
            elif request.domain.endswith(self.root_domain):
                self.domains[request.domain] = True
                check = True

        if check:
            host = Host(request.domain)
            domain_report(host, report.add_message, report.add_warning)

        if request.source == self.name and not request.domain == self.main_domain:
            report.add_warning('Not redirecting to main domain')
