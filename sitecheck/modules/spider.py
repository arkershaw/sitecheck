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
import os
import urllib.parse
import urllib.request
from subprocess import Popen, TimeoutExpired, PIPE
from sitecheck.reporting import requires_report
from sitecheck.core import ModuleBase, HtmlHelper


class StatusLog(ModuleBase):
    def process(self, request, response, report):
        if response.status >= 400:
            report.add_message('Status: [{0} {1}]'.format(response.status, response.message))
            if request.referrer and len(request.referrer) > 0:
                report.add_message('Referrer: [{0}]'.format(request.referrer))


class RequiredPages(ModuleBase):
    def __init__(self, *args):
        super(RequiredPages, self).__init__()
        self.pages = set(args)
        self.total = len(self.pages)
        self.root_path = ''
        self.root_path_length = len(self.root_path)

    def begin(self):
        self.root_path = urllib.parse.urlparse(self.sitecheck.session.domain).path
        self.root_path_length = len(self.root_path)

    def process(self, request, response, report):
        with self.sync_lock:
            self.pages.discard(str(request))
            rp = urllib.parse.urlparse(str(request)).path
            if rp.startswith(self.root_path):
                self.pages.discard(rp[self.root_path_length:])

    @requires_report
    def complete(self, report):
        if len(self.pages) > 0:
            report.add_message('{0}/{1} pages unmatched\n'.format(len(self.pages), self.total))
            for p in self.pages:
                report.add_message(p)


class RequestList(ModuleBase):
    def __init__(self, *args):
        super(RequestList, self).__init__()
        self.requests = args

    def begin(self):
        if len(self.requests) > 0:
            req = self.requests[0]
            req.sequence = 1
            req.source = self.name
            self.sitecheck.request_queue.put(req)

    def process(self, request, response, report):
        with self.sync_lock:
            if request.source == self.name:
                if request.sequence < len(self.requests):
                    req = self.requests[request.sequence]
                    req.referrer = str(request)
                    req.sequence = request.sequence + 1
                    req.source = self.name
                    self.sitecheck.request_queue.put(req)


class Spider(ModuleBase):
    def _log_url(self, url):
        if url == None:
            return False
        if len(url) == 0:
            return False
        if url.startswith('#'):
            return False

        parts = urllib.parse.urlparse(url)
        # if (parts.netloc == request.domain or len(parts.netloc) == 0) and parts.path == request.path:
        #	return False

        if re.match('^http', parts.scheme, re.IGNORECASE) or len(parts.scheme) == 0:
            return True
        else:
            return False

    def _report(self, report, urls):
        out = list(urls)
        if len(out) > 0:
            out.sort()
            for url in out:
                if url.count(' ') > 0:
                    report.add_message('-> [{0}] *Unencoded'.format(url))
                else:
                    report.add_message('-> [{0}]'.format(url))

    def process(self, request, response, report):
        if response.is_html:
            doc = HtmlHelper(response.content)

            referrer = str(request)

            self._add_request([e[2] for e in doc.get_attribute('src')], referrer)
            self._add_request([e[2] for e in doc.get_attribute('action', 'form')], referrer)

            urls = set()
            for href in doc.get_attribute('href'):
                if href[0] == 'a':
                    if self._log_url(href[2]):
                        urls.add(href[2])
                self._add_request(href[2], referrer)

            self._report(report, urls)


class JavascriptSpider(Spider):
    def __init__(self, phantom_js_path='phantomjs'):
        super(JavascriptSpider, self).__init__()
        self.phantom_js_path = phantom_js_path

    def process(self, request, response, report):
        if response.is_html:
            referrer = str(request)

            pth = os.path.dirname(os.path.realpath(__file__))
            proc = Popen([self.phantom_js_path, '{0}{1}scrape.js'.format(pth, os.sep), referrer], stdin=PIPE, stdout=PIPE, stderr=PIPE)

            try:
                out, err = proc.communicate(response.content.encode(), timeout=10)
                rc = proc.returncode
            except TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
                if len(err) > 0:
                    report.add_error(err.decode('utf-8'))
                else:
                    report.add_error(out.decode('utf-8'))
            else:
                if rc == 0:
                    result = out.decode('utf-8').strip()
                    urls = set()
                    for url in set(result.splitlines()):
                        if self._log_url(url):
                            urls.add(url)
                        self._add_request(url, referrer)

                    self._report(report, urls)
                else:
                    if len(err) > 0:
                        report.add_error(err.decode('utf-8'))
                    else:
                        report.add_error(out.decode('utf-8'))
