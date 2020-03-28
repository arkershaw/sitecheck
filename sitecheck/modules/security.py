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
from sitecheck.core import ModuleBase, HtmlHelper


class Authenticate(ModuleBase):
    AUTH_META_KEY = '__AUTHENTICATION'
    LOGIN = 'Login'
    LOGOUT = 'Logout'

    def __init__(self, login=None, logout=None):
        super(Authenticate, self).__init__()
        self.login = login if login else []
        self.logout = logout if logout else []

    def initialise(self, sitecheck):
        super(Authenticate, self).initialise(sitecheck)

        for req in self.logout:
            if not str(req) in self.sitecheck.session.ignore_url:
                self.sitecheck.session.ignore_url.append(str(req))

        if len(self.login) > 0:
            req = self.login[0]
            req.sequence = 1
            req.source = self.name
            req.meta[Authenticate.AUTH_META_KEY] = Authenticate.LOGIN
            req.modules = [self]
            self.sitecheck.request_queue.put(req)

    def _log(self, request, response, report, message=None):
        if message:
            report.add_message(message)
        report.add_message('Method: [{0}]'.format(request.verb))
        report.add_message('Status: [{0}]'.format(str(response.status)))
        report.add_message('Request Headers: {0}'.format(request.headers))
        report.add_message('Response Headers: {0}\n'.format(response.headers))

        if response.status >= 400:
            report.add_error('Authentication Failed')
            if len(request.post_data) > 0:
                report.add_message('Post Data: {0}'.format(request.post_data))
        elif self.sitecheck.session.log.post_data and len(request.post_data) > 0:
            report.add_message('Post Data: {0}'.format(request.post_data))

    def process(self, request, response, report):
        if request.source == self.name:
            if request.meta[Authenticate.AUTH_META_KEY] == Authenticate.LOGIN:
                self._log(request, response, report, 'Authenticating')
                if request.sequence < len(self.login):
                    req = self.login[request.sequence]
                    req.referrer = str(request)
                    req.sequence = request.sequence + 1
                    req.source = self.name
                    req.meta[Authenticate.AUTH_META_KEY] = Authenticate.LOGIN
                    req.modules = [self]
                    self.sitecheck.request_queue.put(req)
                else:
                    self.sitecheck._begin()
            elif request.meta[Authenticate.AUTH_META_KEY] == Authenticate.LOGOUT:
                self._log(request, response, report, 'Logging out')
                if request.sequence < len(self.logout):
                    req = self.logout[request.sequence]
                    req.referrer = str(request)
                    req.sequence = request.sequence + 1
                    req.source = self.name
                    req.meta[Authenticate.AUTH_META_KEY] = Authenticate.LOGOUT
                    self.sitecheck.request_queue.put(req)
                else:
                    # Now scan all the login pages
                    for req in self.login:
                        self.sitecheck.request_queue.put_url('', str(req), self.sitecheck.session.domain)

    def end(self):
        if len(self.logout) > 0:
            for req in self.logout:
                if str(req) in self.sitecheck.session.ignore_url:
                    self.sitecheck.session.ignore_url.remove(str(req))

            req = self.logout[0]
            req.sequence = 1
            req.source = self.name
            req.meta[Authenticate.AUTH_META_KEY] = Authenticate.LOGOUT
            self.sitecheck.request_queue.put(req)


class Security(ModuleBase):
    def __init__(self, email='', attacks=None, quick=True, post=True):
        super(Security, self).__init__()
        self.xss = re.compile("<xss>", re.IGNORECASE)
        self.email = email
        self.attacks = attacks if attacks else []
        self.quick = quick
        self.post = post

    def _build_query(self, items):
        # Unsafe encoding is required for this module
        query_out = []
        keys = list(items.keys())
        keys.sort()
        for k in keys:
            if type(items[k]) is list:
                for i in items[k]:
                    query_out.append('{0}={1}'.format(k, i))
            else:
                query_out.append('{0}={1}'.format(k, items[k]))

        return '&'.join(query_out)

    def process(self, request, response, report):
        if request.source == self.name:
            err = False
            if response.status >= 500:
                err = True
                report.add_warning('Possible SQL injection')
            elif self.xss.search(response.content):
                err = True
                report.add_warning('Possible XSS')

            if 'vector' in request.meta and err:
                if request.meta['vector'] == 'post_data':
                    report.add_message('Post data: {0}'.format(request.post_data))
                elif request.meta['vector'] == 'headers':
                    report.add_message('Request headers: {0}'.format(request.headers))

        elif response.is_html and response.status < 500:
            # Don't attack error pages - can't tell if it worked without matching against known database error text
            doc = HtmlHelper(response.content)
            for atk in self.attacks:
                if self.quick:
                    self._inject_all(request, doc, atk)
                else:
                    self._inject_each(request, doc, atk)

    def _inject_all(self, request, document, value):
        headers = request.headers.copy()
        for h in headers:
            headers[h] = value
        req = self._create_request(str(request), str(request))
        req.headers = headers
        req.modules = [self]
        req.meta['vector'] = 'headers'
        self.sitecheck.request_queue.put(req)

        if len(request.query) > 0:
            qs = urllib.parse.parse_qs(request.query, keep_blank_values=True)
            for param in qs.keys():
                qs[param] = value

            req = self._create_request(str(request), str(request))
            req.query = self._build_query(qs)
            req.modules = [self]
            req.meta['vector'] = 'querystring'
            self.sitecheck.request_queue.put(req)

        if self.post:
            for f in document.get_elements('form'):
                url, post, params = self._parse_form(f)
                if url:
                    self._add_request(url, str(request))
                else:
                    url = str(request)

                rp = [(p[0], value) for p in params]

                req = self._create_request(url, str(request))
                if post:
                    req.post_data = rp
                    req.meta['vector'] = 'post_data'
                else:
                    if len(req.query) > 0:
                        req.query += '&'
                    req.query += self._build_query(dict(rp))
                    req.meta['vector'] = 'querystring'

                req.modules = [self]
                self.sitecheck.request_queue.put(req)

    def _inject_each(self, request, document, value):
        headers = request.headers.copy()
        for h in headers:
            temp = headers[h]
            headers[h] = value
            req = self._create_request(str(request), str(request))
            req.headers = headers
            req.modules = [self]
            req.meta['vector'] = 'headers'
            self.sitecheck.request_queue.put(req)
            headers[h] = temp

        if len(request.query) > 0:
            qs = urllib.parse.parse_qs(request.query, keep_blank_values=True)
            for param in qs.keys():
                temp = qs[param]
                qs[param] = value
                req = self._create_request(str(request), str(request))
                req.query = self._build_query(qs)
                req.modules = [self]
                req.meta['vector'] = 'querystring'
                self.sitecheck.request_queue.put(req)
                qs[param] = temp

        if self.post:
            for f in document.get_elements('form'):
                url, post, params = self._parse_form(f)
                if url:
                    self._add_request(url, str(request))
                else:
                    url = str(request)

                for cp in params:
                    rp = [self._insert_param(p, cp[0], value) for p in params]  # Construct new list

                    req = self._create_request(url, str(request))
                    if post:
                        req.post_data = rp
                        req.meta['vector'] = 'post_data'
                    else:
                        if len(req.query) > 0:
                            req.query += '&'
                        req.query += self._build_query(dict(rp))
                        req.meta['vector'] = 'querystring'

                    req.modules = [self]
                    self.sitecheck.request_queue.put(req)

    def _parse_form(self, form):
        url = None
        post = False

        for a in form.get_attribute('action', 'form'):
            if len(a[2]) > 0:
                url = a[2]
            break

        for m in form.get_attribute('method', 'form'):
            if m[2].upper() == 'POST':
                post = True
            break

        params = []

        for e in form.get_elements(['input', 'textarea', 'select']):
            name = ''
            for n in e.get_attribute('name'):
                name = n[2]
                break

            if len(name) > 0:
                val = ''
                for v in e.get_attribute('value'):
                    val = v[2]
                    break

                if len(val) == 0:
                    if name.lower().find('date') > -1:
                        val = '2000-1-1'
                    elif name.lower().find('email') > -1:
                        val = self.email
                    else:
                        val = '1'

                params.append((name, val))

        return url, post, params

    def _insert_param(self, item, name, value):
        if item[0] == name:
            return name, value
        else:
            return item
