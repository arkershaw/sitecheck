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
import sys
import urllib.parse
import urllib.request
import base64
from sitecheck.reporting import ensure_dir, requires_report
from sitecheck.core import ModuleBase, HtmlHelper, TextHelper

try:
    from tidylib import tidy_document
except ModuleNotFoundError:
    _tidy_available = False
else:
    _tidy_available = True


class Spelling(ModuleBase):
    def __init__(self, dictionary_path='en_US'):
        super(Spelling, self).__init__()
        self.sentence_end = '!?.'
        self.dictionary_path = dictionary_path
        self.dictionary = None

    def __getstate__(self):
        state = self._clean_state(dict(self.__dict__))
        del state['dictionary']
        return state

    def _read_dictionary(self, dict_path):
        self.dictionary = [w.strip().lower() for w in open(dict_path, 'r').read().splitlines()]

    def initialise(self, sitecheck):
        super(Spelling, self).initialise(sitecheck)

        # Load the dictionary when check is resumed
        if os.path.isabs(self.dictionary_path):
            dict_path = self.dictionary_path
        else:
            dict_path = os.path.join(self.sitecheck.session.root_path, self.dictionary_path)

        try:
            self._read_dictionary(dict_path)
        except:
            self.dictionary = None

    @requires_report
    def begin(self, report):
        if not self.dictionary:
            report.add_error('Unable to open dictionary - using default.')
            dict_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'en-basic.txt')
            self._read_dictionary(dict_path)

    def process(self, request, response, report):
        if response.is_html:
            doc = HtmlHelper(response.content)
            doc.strip_comments()
            doc.strip_elements(('script', 'style'))

            words = {}
            with self.sync_lock:
                for txt in doc.get_text():
                    self._check(txt, words)
                for txt in doc.get_attribute('title'):
                    self._check(txt[2], words)
                for txt in doc.get_attribute('alt'):
                    self._check(txt[2], words)
                for e in doc.get_elements('meta'):
                    names = [n for n in e.get_attribute('name')]
                    if len(names) > 0:
                        name = names[0][2].lower()
                        if name == 'description' or name == 'keywords':
                            content = [c for c in e.get_attribute('content')]
                            if len(content) > 0:
                                self._check(content[0][2], words)

            if len(words) > 0:
                keys = list(words.keys())
                keys.sort()
                for k in keys:
                    report.add_message('Word: [{0}] x {1} ({2})'.format(words[k][0], words[k][1], words[k][2]))

    def _check(self, text, words):
        if not text:
            return
        t = HtmlHelper.html_decode(text.strip())
        text_length = len(t)
        if text_length > 0:
            split_words = re.split(r'\W+', text)
            # TODO: Strip apostrophes from words
            # TODO: Ignore plurals of dictionary words ending in s
            for w in split_words:
                # Check second letter is lowercase to avoid abbreviations.
                if len(w) > 1 and w[1].islower():
                    lw = w.lower()
                    found = False
                    if lw in self.dictionary:
                        found = True
                    elif lw.endswith('s') and lw[:-1] in self.dictionary:
                        found = True

                    if not found:
                        if lw in words:
                            words[lw][1] += 1
                        else:
                            m = re.search(r'(.)?\s*\b(%s)\b' % w, t)
                            if m:
                                # First word in sentence/para or not proper noun.
                                if m.start() == 0 or m.group(1) in self.sentence_end or m.group(2)[0].islower():
                                    st = max(m.start() - 20, 0)
                                    en = min(m.end() + 20, text_length)
                                    ctx = re.sub('[\t\n]', ' ', t[st:en])
                                    words[lw] = [w, 1, ctx]


class Accessibility(ModuleBase):
    def __init__(self):
        super(Accessibility, self).__init__()
        self.accessibility = re.compile(r' - Access: \[([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\]')
        self.ignore = set()
        self.ignore.add('1.1.2.1')  # <img> missing 'longdesc' and d-link
        self.ignore.add('2.1.1')  # ensure information not conveyed through color alone.
        self.ignore.add('6.1.1')  # style sheets require testing
        self.ignore.add('6.2.2')  # text equivalents require updating
        self.ignore.add('6.3.1')  # programmatic objects require testing
        self.ignore.add('7.1.1')  # remove flicker
        self.ignore.add('8.1.1')  # ensure programmatic objects are accessible

        self.options = {'show-warnings': False, 'accessibility-check': 1}

    @requires_report
    def begin(self, report):
        global _tidy_available
        if not _tidy_available:
            report.add_error('HTML Tidy not available')

    def process(self, request, response, report):
        global _tidy_available
        # TODO: Hash errors and don't log duplicate error sets (just a reference)
        if response.is_html and _tidy_available:
            try:
                doc, err = tidy_document(response.content, options=self.options)
            except:
                ex = sys.exc_info()
                report.add_error('Error {0} {1}'.format(str(ex[0]), str(ex[1])))
            else:
                c = 0
                for e in err.splitlines():
                    if self._log(e):
                        c += 1
                        report.add_message('{0}'.format(re.sub('^line\\b', 'Line', e)))

                if c > 0:
                    report.add_message('Total: {0}'.format(c))

    def _log(self, error):
        match = self.accessibility.search(error)
        log = False
        if match:
            log = True
            txt = ''
            for grp in match.groups():
                if len(txt) > 0:
                    txt += '.'
                txt += grp
                if txt in self.ignore:
                    log = False
                    break
        return log


class Comments(ModuleBase):
    def process(self, request, response, report):
        if response.is_html:
            doc = HtmlHelper(response.content)
            for comment in doc.get_comments():
                c = comment.strip()
                if c.startswith('[if') and c.endswith('<![endif]'):
                    # Ignore IE conditional comments
                    pass
                else:
                    report.add_message('Comment:\t{0}'.format(re.sub('\r?\n', '\n\t\t\t\t', c, re.MULTILINE)))


class Readability(ModuleBase):
    def __init__(self, threshold=45):
        super(Readability, self).__init__()
        self.threshold = threshold
        self.min = None
        self.max = None
        self.count = 0
        self.total = 0

    @requires_report
    def complete(self, report):
        if self.count > 0:
            report.add_message('\nSummary: Min {:.2f}, Max {:.2f}, Avg {:.2f}'.format(self.min, self.max, self.total / self.count))

    def process(self, request, response, report):
        if response.is_html:
            doc = HtmlHelper(response.content)
            doc.strip_comments()
            doc.strip_elements(('script', 'style'))

            th = TextHelper()
            for txt in doc.get_text():
                th.append(txt)

            if len(th) > 0:
                twrd = float(th.word_count())
                tsnt = float(th.sentence_count())
                tsyl = float(th.syllable_count())

                fkre = 206.835 - 1.015 * (twrd / tsnt) - 84.6 * (tsyl / twrd)

                with self.sync_lock:
                    self.count += 1
                    self.total += fkre
                    if self.min is None:
                        self.min = fkre
                    else:
                        self.min = min(self.min, fkre)

                    if self.max is None:
                        self.max = fkre
                    else:
                        self.max = max(self.max, fkre)

                if fkre < self.threshold:
                    report.add_message('Readability: [{1:.2f}]'.format(str(request), fkre))


class Validator(ModuleBase):
    def __init__(self):
        super(Validator, self).__init__()
        self.options = {'show-warnings': True}

    @requires_report
    def begin(self, report):
        global _tidy_available
        if not _tidy_available:
            report.add_error('HTML Tidy not available')

    def process(self, request, response, report):
        global _tidy_available
        # TODO: Hash errors and don't log duplicate error sets (just a reference)
        if response.is_html and _tidy_available:
            try:
                doc, err = tidy_document(response.content, options=self.options)
            except:
                ex = sys.exc_info()
                report.add_error('Error {0} {1}'.format(str(ex[0]), str(ex[1])))
            else:
                l = err.splitlines()
                if len(l) > 0:
                    for e in l:
                        report.add_message('{0}'.format(re.sub('^line\\b', 'Line', e)))

                    report.add_message('Total: {0}'.format(len(l)))


class RegexMatch(ModuleBase):
    def __init__(self, expressions=None):
        super(RegexMatch, self).__init__()
        self.expressions = expressions if expressions else {}

    def process(self, request, response, report):
        for rx in self.expressions.items():
            inv_h = inv_b = False
            if rx[0][0] == '^':
                inv_h = True
            elif rx[0][0] == '_':
                inv_b = True

            if inv_h:
                if not rx[1].search(str(response.headers)):
                    report.add_message('Filter: [{0}] not found in headers'.format(rx[0]))
            elif not inv_b:
                matches = rx[1].finditer(str(response.headers))
                for match in matches:
                    report.add_message('Filter: [{0}] found: [{1}] in headers'.format(rx[0], match.group()))

            if response.is_html:
                if inv_b:
                    if not rx[1].search(str(response.content)):
                        report.add_message('Filter: [{0}] not found'.format(rx[0]))
                elif not inv_h:
                    matches = rx[1].finditer(response.content)
                    for match in matches:
                        report.add_message('Filter: [{0}] found: [{1}]'.format(rx[0], match.group()))


class Persister(ModuleBase):
    def __init__(self, directory='output'):
        super(Persister, self).__init__()
        self.directory = directory

    def process(self, request, response, report):
        if request.verb == 'HEAD' and response.status < 300 and request.domain == urllib.parse.urlparse(self.sitecheck.session.domain).netloc:
            req = self._create_request(str(request), request.referrer)
            req.verb = 'GET'
            req.modules = [self]
            self.sitecheck.request_queue.put(req)
        elif len(response.content) > 0 and response.status < 300:
            od = self.sitecheck.session.root_path + self.sitecheck.session.output + os.sep
            if len(self.directory) >  0:
                od += self.directory + os.sep
            od += request.domain

            parts = request.path.split('/')
            if len(parts) > 1:
                if parts[-1] == '':
                    parts[-1] = '__index'
                od += os.sep.join(parts[0:-1])
                fl = parts[-1]
            else:
                fl = '__index'

            ensure_dir(od)

            if len(request.query) > 0:
                fl += '+' + base64.urlsafe_b64encode(('?' + request.query).encode()).decode('utf-8')

            if response.is_html and not re.search(r'\.html?$', fl, re.IGNORECASE):
                fl += '.html'

            pth = os.path.join(od, fl)

            if response.is_html:
                open(pth, mode='w').write(response.content)
            else:
                open(pth, mode='wb').write(response.content)
