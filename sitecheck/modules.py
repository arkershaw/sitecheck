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
import hashlib
import urllib.parse
import urllib.request
from io import StringIO
import json
import base64
from subprocess import Popen, TimeoutExpired, PIPE

try:
    from tidylib import tidy_document
except:
    _tidy_available = False
else:
    _tidy_available = True

try:
    from enchant import Dict, DictWithPWL
    from enchant.checker import SpellChecker
    from enchant.tokenize import EmailFilter, URLFilter
except:
    _enchant_available = False
else:
    _enchant_available = True


from domaincheck import check_domain
from sitecheck.reporting import ensure_dir, requires_report
from sitecheck.core import Authenticate, ModuleBase, HtmlHelper, TextHelper

__all__ = [
    'Authenticate', 'RequestList', 'RequiredPages', 'DuplicateContent', 'InsecureContent', 'DomainCheck', 'Persister',
    'InboundLinks', 'RegexMatch', 'Validator', 'Accessibility', 'MetaData', 'StatusLog', 'Security', 'Comments',
    'Spelling', 'Readability', 'Spider', 'JavascriptSpider'
]


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


class StatusLog(ModuleBase):
    def process(self, request, response, report):
        if response.status >= 400:
            report.add_message('Status: [{0} {1}]'.format(response.status, response.message))
            if request.referrer and len(request.referrer) > 0:
                report.add_message('Referrer: [{0}]'.format(request.referrer))


class Accessibility(ModuleBase):
    def __init__(self):
        super(Accessibility, self).__init__()
        self.accessibility = re.compile(r' - Access: \[([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\]')
        self.ignore = set()
        self.ignore.add('1.1.2.1') # <img> missing 'longdesc' and d-link
        self.ignore.add('2.1.1') # ensure information not conveyed through color alone.
        self.ignore.add('6.1.1') # style sheets require testing
        self.ignore.add('6.2.2') # text equivalents require updating
        self.ignore.add('6.3.1') # programmatic objects require testing
        self.ignore.add('7.1.1') # remove flicker
        self.ignore.add('8.1.1') # ensure programmatic objects are accessible

        self.options = {'show-warnings': False, 'accessibility-check': 1}

    @requires_report
    def begin(self, report):
        global _tidy_available
        if not _tidy_available:
            report.add_error('tidylib not available')

    def process(self, request, response, report):
        global _tidy_available
        # TODO: Hash errors and don't log duplicate error sets (just a reference)
        if response.is_html and _tidy_available:
            try:
                doc, err = tidy_document(response.content, options=self.options)
            except:
                report.add_message('Error parsing: [{0}]'.format(str(request)))
            else:
                c = 0
                for e in err.splitlines():
                    if self._log(e):
                        c += 1
                        report.add_message('{0}'.format(re.sub('^line\\b', 'Line', e)))

                if c > 0:
                    report.add_message('Total: {0}'.format(c))

    def _log(self, error):
        mtch = self.accessibility.search(error)
        log = False
        if mtch:
            log = True
            txt = ''
            for grp in mtch.groups():
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
            report.add_error('tidylib not available')

    def process(self, request, response, report):
        global _tidy_available
        # TODO: Hash errors and don't log duplicate error sets (just a reference)
        if response.is_html and _tidy_available:
            try:
                doc, err = tidy_document(response.content, options=self.options)
            except:
                report.add_error('Unable to parse response')
            else:
                l = err.splitlines()
                if len(l) > 0:
                    for e in l:
                        report.add_message('{0}'.format(re.sub('^line\\b', 'Line', e)))

                    report.add_message('Total: {0}'.format(len(l)))


class RegexMatch(ModuleBase):
    def __init__(self, expressions={}):
        super(RegexMatch, self).__init__()
        self.expressions = expressions

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
                mtchs = rx[1].finditer(str(response.headers))
                for mtch in mtchs:
                    report.add_message('Filter: [{0}] found: [{1}] in headers'.format(rx[0], mtch.group()))

            if response.is_html:
                if inv_b:
                    if not rx[1].search(str(response.content)):
                        report.add_message('Filter: [{0}] not found'.format(rx[0]))
                elif not inv_h:
                    mtchs = rx[1].finditer(response.content)
                    for mtch in mtchs:
                        report.add_message('Filter: [{0}] found: [{1}]'.format(rx[0], mtch.group()))


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

            if response.is_html and not re.search('\.html?$', fl, re.IGNORECASE):
                fl += '.html'

            pth = os.path.join(od, fl)

            if response.is_html:
                open(pth, mode='w').write(response.content)
            else:
                open(pth, mode='wb').write(response.content)


class Spelling(ModuleBase):
    def __init__(self, language='en_US'):
        super(Spelling, self).__init__()
        self.language = language
        self.sentence_end = '!?.'
        self.dictionary = None
        self.spell_checker = None

    def __getstate__(self):
        state = self._clean_state(dict(self.__dict__))
        del state['spell_checker']
        return state

    def initialise(self, sitecheck):
        super(Spelling, self).initialise(sitecheck)

        # Spell checker must be re-created when check is resumed
        global _enchant_available
        if _enchant_available:
            ddp = os.path.dirname(os.path.abspath(__file__)) + 'dict.txt'
            cdp = self.sitecheck.session.root_path + 'dict.txt'

            if os.path.exists(cdp):
                self.dictionary = cdp
                d = DictWithPWL(self.language, cdp)
            elif os.path.exists(ddp):
                self.dictionary = ddp
                d = DictWithPWL(self.language, ddp)
            else:
                d = Dict(self.language)

            self.spell_checker = SpellChecker(d, filters=[EmailFilter, URLFilter])

    @requires_report
    def begin(self, report):
        if self.spell_checker:
            report.add_message('Language: {0}'.format(self.language))
            if self.dictionary:
                report.add_message('Using custom dictionary [{0}]'.format(self.dictionary))
        else:
            report.add_error('pyenchant not available')

    def process(self, request, response, report):
        global _enchant_available
        if response.is_html and _enchant_available:
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
        l = len(t)
        if l > 0:
            self.spell_checker.set_text(t)
            # import pdb; pdb.set_trace()
            # TODO: Strip apostrophes from words
            # TODO: Ignore plurals of dictionary words ending in s
            for err in self.spell_checker:
                if len(err.word) > 1 and err.word[1].islower():  # Ignore abbreviations
                    w = err.word.lower()
                    if w in words:
                        words[w][1] += 1
                    else:
                        ctx = ''
                        m = re.search(r'(.)?\s*\b(%s)\b' % err.word, t)
                        if m:
                            # First word in sentence/para or not proper noun.
                            if m.start() == 0 or m.group(1) in self.sentence_end or m.group(2)[0].islower():
                                st = max(m.start() - 20, 0)
                                en = min(m.end() + 20, l)
                                ctx = re.sub('[\t\n]', ' ', t[st:en])
                                words[w] = [err.word, 1, ctx]


class InboundLinks(ModuleBase):
    def __init__(self, engines=None):
        super(InboundLinks, self).__init__()
        self.domain = ''
        self.link = ''
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
                settings = urllib.request.urlopen('http://www.site-check.co.uk/search-engines.js').read().decode('utf-8')
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
                req.verb = 'GET' # Otherwise it will be set to HEAD as it is on another domain
                self.sitecheck.request_queue.put(req)
            else:
                report.add_error('Unknown search engine: [{0}]'.format(se))
                self.engines.pop(ei)

    def process(self, request, response, report):
        if request.source == self.name and response.is_html and request.referrer in self.engine_parameters:
            with self.sync_lock:
                e = self.engine_parameters[request.referrer]
                mtch = e[1].search(response.content)
                if mtch:
                    e[4] = int(re.sub('[^0-9]', '', mtch.groups()[0]))

                    for m in self.link.finditer(response.content):
                        url = m.groups()[0]
                        self.inbound.add(url)
                        self._add_request(url, str(request))

                    e[5] += e[2]
                    if e[5] < e[4]:
                        url = e[0].format(domain=self.domain, index=e[5])
                        req = self._create_request(url, request.referrer)
                        req.modules = [self]
                        req.verb = 'GET' # Otherwise it will be set to HEAD as it is on another domain
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


class Security(ModuleBase):
    def __init__(self, email='', attacks=[], quick=True, post=True):
        super(Security, self).__init__()
        self.xss = re.compile("<xss>", re.IGNORECASE)
        self.email = email
        self.attacks = attacks
        self.quick = quick
        self.post = post

    def _build_query(self, items):
        # Unsafe encoding is required for this module
        qsout = []
        keys = list(items.keys())
        keys.sort()
        for k in keys:
            if type(items[k]) is list:
                for i in items[k]:
                    qsout.append('{0}={1}'.format(k, i))
            else:
                qsout.append('{0}={1}'.format(k, items[k]))

        return '&'.join(qsout)

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
        hdrs = request.headers.copy()
        for h in hdrs:
            hdrs[h] = value
        req = self._create_request(str(request), str(request))
        req.headers = hdrs
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
        hdrs = request.headers.copy()
        for h in hdrs:
            temp = hdrs[h]
            hdrs[h] = value
            req = self._create_request(str(request), str(request))
            req.headers = hdrs
            req.modules = [self]
            req.meta['vector'] = 'headers'
            self.sitecheck.request_queue.put(req)
            hdrs[h] = temp

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
                    rp = [self._insert_param(p, cp[0], value) for p in params] # Construct new list

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
            return (name, value)
        else:
            return item


class DomainCheck(ModuleBase):
    def __init__(self, domains=[], relay=False):
        super(DomainCheck, self).__init__()
        self.domains = domains
        self.relay = relay

    @requires_report
    def begin(self, report):
        check_domain(self.sitecheck.session.domain, self.relay, report.add_message, report.add_warning)
        for domain in self.domains:
            check_domain(domain, self.relay, report.add_message, report.add_warning)
            url = 'http://{0}'.format(domain)
            req = self._create_request(url, url)
            req.modules = [self]
            self.sitecheck.request_queue.put(req)

    def process(self, request, response, report):
        if request.source == self.name and not request.domain == self.sitecheck.session.domain:
            report.add_warning('Not redirecting to main domain')


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


class InsecureContent(ModuleBase):
    def process(self, request, response, report):
        if response.is_html and request.protocol.lower() == 'https':
            doc = HtmlHelper(response.content)

            for e, a, v in doc.get_attribute('src'): #img, script
                if v.lower().startswith('http:'):
                    report.add_message('{0}'.format(v))

            for e, a, v in doc.get_attribute('href', 'link'):
                if v.lower().startswith('http:'):
                    report.add_message('{0}'.format(v))


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
