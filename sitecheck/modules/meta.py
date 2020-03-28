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

import hashlib
from sitecheck.core import ModuleBase, HtmlHelper


class MetaData(ModuleBase):
    def process(self, request, response, report):
        if response.is_html:
            doc = HtmlHelper(response.content)
            missing = []
            empty = []
            multiple = []

            title = [t for t in doc.get_elements('title')]
            if len(title) == 0:
                missing.append('title')
            elif len(title) > 1:
                multiple.append('title')
            else:
                txt = [t for t in title[0].get_text()]
                if len(txt) == 0:
                    empty.append('title')

            meta = {'description': [0, ''], 'keywords': [0, '']}
            for e in doc.get_elements('meta'):
                names = [n for n in e.get_attribute('name')]
                if len(names) > 0:
                    name = names[0][2].lower()
                    if name in meta:
                        meta[name][0] += 1
                        content = [c for c in e.get_attribute('content')]
                        if len(content[0][2]) > 0:
                            meta[name][1] = content[0][2]

            for m in meta:
                if meta[m][0] == 0:
                    missing.append(m)
                elif meta[m][0] > 1:
                    multiple.append(m)
                elif len(meta[m][1]) == 0:
                    empty.append(m)

            if len(missing) > 0:
                report.add_message('Missing: {0}'.format(str(missing)))

            if len(empty) > 0:
                report.add_message('Empty: {0}'.format(str(empty)))

            if len(multiple) > 0:
                report.add_message('Multiple: {0}'.format(str(multiple)))


class InsecureContent(ModuleBase):
    def process(self, request, response, report):
        if response.is_html and request.protocol.lower() == 'https':
            doc = HtmlHelper(response.content)

            for e, a, v in doc.get_attribute('src'):  # img, script
                if v.lower().startswith('http:'):
                    report.add_message('{0}'.format(v))

            for e, a, v in doc.get_attribute('href', 'link'):
                if v.lower().startswith('http:'):
                    report.add_message('{0}'.format(v))


class DuplicateContent(ModuleBase):
    def __init__(self, content=True, content_length=25):
        super(DuplicateContent, self).__init__()
        self.content = content
        self.content_length = content_length
        self.pages = {}
        self.paras = {}

    def begin(self):
        self.pages = {}
        self.paras = {}

    def process(self, request, response, report):
        if response.is_html and response.status < 300:
            m = hashlib.sha1()
            m.update(response.content.encode())
            h = m.hexdigest()

            dup = False
            with self.sync_lock:
                if h in self.pages:
                    if str(request) != self.pages[h]:
                        report.add_message('Duplicate of: {0}'.format(self.pages[h]))
                        dup = True
                else:
                    self.pages[h] = str(request)

                if self.content and not dup:
                    doc = HtmlHelper(response.content)
                    text = [t for t in doc.get_text(['div', 'p']) if len(t) >= self.content_length]
                    text.sort(key=lambda k: len(k), reverse=True)
                    for t in text:
                        m = hashlib.sha1()
                        m.update(t.encode())
                        h = m.hexdigest()

                        if h in self.paras:
                            if str(request) != self.paras[h]:
                                report.add_message(t[0:self.content_length] + '...')
                                report.add_message('Duplicated from: {0}'.format(self.paras[h]))
                        else:
                            self.paras[h] = str(request)
