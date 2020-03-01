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

import sys
import os
import threading
import time
import http.client
import urllib.parse
import http.cookies
import socket
import queue
import re
import hashlib
import uuid
import html.entities
import copy

from sitecheck.reporting import ReportThread, OutputQueue, ReportData

VERSION = '1.8'
CONTACT_EMAIL = 'andy@site-check.co.uk'


class SiteCheck(object):
    def __init__(self, settings):
        self.output_queue = OutputQueue()
        self.request_queue = None
        self.report_thread = None
        self._started = False
        self._threads = []
        self.sleep_time = 5

        if type(settings) == tuple:
            self._resume_data = settings
            self._set_session(self._resume_data[0])

            if hasattr(self.session, '_cookie'):
                del self.session._cookie
        else:
            self._resume_data = None
            self._set_session(settings)

    def _set_session(self, session):
        if self._started:
            raise SiteCheckStartedException()

        self.session = session
        self.request_queue = RequestQueue(session)

        if not hasattr(self.session, '_debug'):
            self.session._debug = False

        if len(os.path.splitext(self.session.domain)[1]) == 0:
            self.session.domain = append(self.session.domain, '/')

        if not re.match('^http', self.session.domain, re.IGNORECASE):
            self.session.domain = 'http://{0}'.format(self.session.domain)

        if len(urllib.parse.urlparse(self.session.domain).netloc) == 0:
            raise Exception('Invalid domain')

        # Organise file type sets
        self.session.include_ext = self.session.include_ext.difference(self.session.ignore_ext)
        self.session.test_ext = self.session.test_ext.difference(self.session.ignore_ext.union(self.session.include_ext))

    def _initialise_module(self, module):
        if not hasattr(module, 'source'):
            self.output_queue.put_error('Module {0} has no source'.format(module.__class__.__name__))
            return False

        if not hasattr(module, 'name'):
            self.output_queue.put_error('Module {0} has no name'.format(module.__class__.__name__), module.source)
            return False

        if not hasattr(module, 'initialise'):
            self.output_queue.put_error('Initialise method not defined in module {0}'.format(module.name), module.source)
            return False

        if not hasattr(module, 'process'):
            self.output_queue.put_error('Process method not defined in module {0}'.format(module.name), module.source)
            return False

        try:
            module.initialise(self)
        except:
            if self.session._debug:
                raise
            self.output_queue.put_error('{0} in module {1}'.format(str(sys.exc_info()[1]), module.name), module.source)
            return False
        else:
            return True

    @property
    def complete(self):
        if self.session is None:
            raise SessionNotSetException()

        if not self._started:
            return False

        cmpl = False
        if self.request_queue.empty():
            cmpl = True
            for t in self._threads:
                if t.active:
                    cmpl = False

        return cmpl

    @property
    def started(self):
        return self._started

    def begin(self, background=False):
        if self.session is None:
            raise SessionNotSetException()
        if self._started:
            raise SiteCheckStartedException()

        self._started = True

        # Start output thread
        self.report_thread = ReportThread(self)
        self.report_thread.setDaemon(True)
        self.report_thread.start()

        # Initialise modules
        self.session.modules = [m for m in self.session.modules if self._initialise_module(m)]

        # Create worker thread pool
        for i in range(self.session.thread_pool):
            thread = Checker(self)
            thread.setDaemon(True)
            thread.start()
            self._threads.append(thread)

        # Unless a module has added a start page
        if self.request_queue.empty():
            self._begin()

        if not background:
            self._wait()
            self.end()

    def _begin(self):
        if self._resume_data:
            for module in self.session.modules:
                if hasattr(module, 'resume'):
                    try:
                        module.resume()
                    except:
                        if self.session._debug:
                            raise
                        self.output_queue.put_error('{0} in module {1}'.format(str(sys.exc_info()[1]), module.name), module.source)
                        self.session.modules.remove(module)
            self.request_queue.load(self._resume_data[1], self._resume_data[2], self._resume_data[3])
            del self._resume_data
        else:
            self.request_queue.requests = set()  # Clear authentication requests
            for module in self.session.modules:
                if hasattr(module, 'begin'):
                    try:
                        module.begin()
                    except:
                        if self.session._debug:
                            raise
                        self.output_queue.put_error('{0} in module {1}'.format(str(sys.exc_info()[1]), module.name), module.source)
                        self.session.modules.remove(module)
            self.request_queue.put_url('', self.session.page, self.session.domain)

    def _wait(self):
        while True:
            if self.complete:
                break
            else:
                time.sleep(self.sleep_time)

    def end(self):
        if self._started:
            if self.session is None:
                raise SessionNotSetException()

            if self.complete:
                for mod in self.session.modules:
                    if hasattr(mod, 'end'):
                        try:
                            mod.end()
                        except:
                            if self.session._debug:
                                raise
                            self.output_queue.put_error('{0} in module {1}'.format(str(sys.exc_info()[1]), mod.name), mod.source)

                self._wait()

                for mod in self.session.modules:
                    if hasattr(mod, 'complete'):
                        try:
                            mod.complete()
                        except:
                            if self.session._debug:
                                raise
                            self.output_queue.put_error('{0} in module {1}'.format(str(sys.exc_info()[1]), mod.name), mod.source)

            # Wait for worker threads to complete
            Checker.terminate.set()
            for thread in self._threads:
                thread.join()

            if self.complete:
                self.output_queue.put_message('Total URLs: {0}'.format(str(len(self.request_queue.urls))))

            # Wait for log entries to be written
            self.report_thread.end()
            self.report_thread.join()

    def suspend(self):
        if self.session is None:
            raise SessionNotSetException()

        dat = self.request_queue.save()

        return self.session, dat[0], dat[1]


# From: http://code.activestate.com/recipes/52308/
class Struct:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def append(content, append):
    if content is None and append is None:
        return ''
    elif content is None:
        return append
    elif append is None:
        return content
    elif content.lower().endswith(append.lower()):
        return content
    else:
        return content + append

#def prepend(content, prepend):
    #if content is None and prepend is None:
        #return ''
    #if content is None:
        #return prepend
    #elif prepend is None:
        #return content
    #elif content.lower().startswith(prepend.lower()):
        #return content
    #else:
        #return prepend + content


def dict_to_sorted_list(dict_obj):
    out = []
    keys = list(dict_obj.keys())
    keys.sort()
    for key in keys:
        val = dict_obj[key]
        if type(val) is list or type(val) is tuple:
            for v in val:
                out.append((key, v))
        else:
            out.append((key, val))
    return out


# From: http://stackoverflow.com/questions/547829/how-to-dynamically-load-a-python-class
def get_module(name):
    mod = __import__(name)
    components = name.split('.')
    for comp in components[1:]:
        mod = getattr(mod, comp)
    return mod


def get_class(name):
    cls = get_module(name)
    return cls()


class SessionNotSetException(Exception):
    pass


class SiteCheckStartedException(Exception):
    pass


class Checker(threading.Thread):
    terminate = threading.Event()

    def __init__(self, sitecheck):
        super(Checker, self).__init__()
        self.active = False  # For determining whether a request is in progress
        self.sitecheck = sitecheck
        self._session = sitecheck.session
        self._output_queue = sitecheck.output_queue
        self._request_queue = sitecheck.request_queue

    def set_verb(self, request):
        if len(request._verb) == 0:
            dom = urllib.parse.urlparse(self._session.domain)
            if not request.domain == dom.netloc:
                # External domain
                request.verb = 'HEAD'
            elif not request.path.startswith(dom.path) and not request.extension in self._session.include_ext:
                # This is hit if path is a file on the current domain but above the current path
                request.verb = 'HEAD'
            elif request.extension in self._session.test_ext:
                request.verb = 'HEAD'

    def set_headers(self, request):
        hdrs = self._session.headers.copy()
        hdrs.update(request.headers)
        request.headers = hdrs
        if 'Content-Type' in request.headers or 'content-type' in request.headers:
            pass
        else:
            request.headers['Content-Type'] = request.encoding

    def set_cookie(self, request):
        if hasattr(self._session, '_cookie'):
            c = self._session._cookie.output(['key', 'coded_value'], '', ';').strip()
            if 'Cookie' in request.headers or 'cookie' in request.headers:
                # request.headers['Cookie'] += c
                # elif 'cookie' in request.headers:
                # request.headers['cookie'] += c
                pass
            else:
                request.headers['Cookie'] = c

    def get_cookie(self, response):
        cookies = response.get_headers('set-cookie')
        if len(cookies) > 0:
            if not hasattr(self._session, '_cookie'):
                self._session._cookie = http.cookies.SimpleCookie()
            for c in cookies:
                self._session._cookie.load(c)

    def process(self, request, response, report):
        if len(request.modules) == 0:
            request.modules = self._session.modules
        for mod in request.modules:
            report.default_source = mod.source
            try:
                mod.process(request, response, report)
            except:
                if self._session._debug:
                    raise
                ex = sys.exc_info()
                report.add_error('Processing failed with module [{0}].'.format(mod.name), mod.source)
                report.add_debug(str(ex[1]), mod.source)
            finally:
                report.default_source = ReportData.DEFAULT_SOURCE

    def fetch(self, request):
        full_path = request.path
        if len(request.query) > 0:
            full_path += '?' + request.query

        if request.protocol == 'https':
            c = http.client.HTTPSConnection(request.domain, timeout=self._session.request_timeout)
        elif request.protocol == 'http':
            c = http.client.HTTPConnection(request.domain, timeout=self._session.request_timeout)
        else:
            return None, 'Unrecognised protocol: {0}'.format(request.protocol)

        res = err = None
        try:
            c.connect()
            st = time.time()
            c.request(request.verb, full_path, request.post_data_string(), request.headers)
            r = c.getresponse()
            res = Response(r, st)
        except socket.gaierror:
            ex = sys.exc_info()
            err = 'DNS error {0} {1}'.format(str(ex[0]), str(ex[1])) # Probably
        except socket.timeout:
            ex = sys.exc_info()
            err = 'Timeout {0} {1}'.format(str(ex[0]), str(ex[1]))
        except http.client.IncompleteRead:
            ex = sys.exc_info()
            err = 'Read error {0} {1}'.format(str(ex[0]), str(ex[1]))
        except:
            ex = sys.exc_info()
            err = 'Error {0} {1}'.format(str(ex[0]), str(ex[1]))
        finally:
            c.close()

        return res, err

    def run(self):
        while not Checker.terminate.isSet():
            self.active = False
            Checker.terminate.wait(self._session.wait_seconds)
            try:
                req = self._request_queue.get(block=False)
            except queue.Empty:
                pass
            else:
                self.active = True

                self.set_verb(req)
                self.set_headers(req)
                self.set_cookie(req)

                res, err = self.fetch(req)

                report = ReportData()
                report.add_message('Method: [{0}]'.format(req.verb), 'request')

                if res:
                    dom = urllib.parse.urlparse(self._session.domain)
                    if req.domain == dom.netloc:
                        self.get_cookie(res)

                    report.add_message('Status: [{0}]'.format(str(res.status)), 'request')
                    if self._session.log.request_headers:
                        report.add_message('Request Headers: {0}'.format(req.headers), 'request')
                    if self._session.log.post_data and len(req.post_data) > 0:
                        report.add_message('Post Data: {0}'.format(req.post_data), 'request')
                    if self._session.log.response_headers:
                        report.add_message('Response Headers: {0}'.format(res.headers), 'request')

                    # Only warn about slow requests once
                    if not hasattr(self._session, '_slow'):
                        self._session._slow = []

                    if res.time > self._session.slow_request and not str(req) in self._session._slow:
                        report.add_warning('Slow request ({0:.3f} seconds)'.format(res.time))
                        self._session._slow.append(str(req))

                    # Only process markup of error pages once
                    if not hasattr(self._session, '_processed'):
                        self._session._processed = []

                    if (300 <= res.status < 400) and req.domain == dom.netloc:
                        locs = res.get_headers('location')
                        if len(locs) > 0:
                            if len(locs) > 1:
                                report.add_error('Multiple redirect locations found')
                                for loc in locs:
                                    report.add_message(loc)

                            redir, msgs = self._request_queue.redirect(req, locs[-1])

                            if not redir:
                                report.add_error(msgs[0])
                                if len(msgs) > 1:
                                    for msg in msgs[1:]:
                                        report.add_message(msg)
                        else:
                            report.add_error('Redirect with no location')
                    elif res.status >= 400 and res.status not in self._session._processed and req.domain == dom.netloc and req.verb == 'HEAD':
                        # If first error page is on a HEAD request, get the resource again
                        req.verb = ''
                        self._request_queue.put(req)
                    else:
                        if res.status >= 400 and req.domain == dom.netloc:
                            if res.status in self._session._processed:
                                res.is_html = False
                            else:
                                self._session._processed.append(res.status)

                        self.process(req, res, report)
                else:
                    if err:
                        report.add_error(err)

                    if not self._request_queue.retry(req):
                        report.add_error('Exceeded max retries')

                self._output_queue.put(req, res, report)


class Request(object):
    def __init__(self, url, post_data=[], referrer=None):
        self.source = ''
        self._referrer = referrer
        self.encoding = 'application/x-www-form-urlencoded'

        self.boundary = None
        self._verb = ''  # Do not default to GET so we can tell if it is set manually or not
        self.redirects = 0
        self.timeouts = 0
        self.sequence = 0
        self.modules = []
        self.post_data = post_data
        self.headers = {}  # Dictionary for httplib
        self.meta = {}

        self.protocol = ''
        self.domain = ''
        self.path = ''
        self.extension = ''
        self.query = ''

        self._set_url(url)

    def _set_url(self, url):
        url = HtmlHelper.html_decode(url.replace(' ', '%20'))
        url_parts = urllib.parse.urlparse(url)

        if len(url_parts.netloc) == 0 and self._referrer:
            # Relative URL - join with referrer
            url = urllib.parse.urljoin(self._referrer, url)
            url_parts = urllib.parse.urlparse(url)

        if len(url_parts.scheme) > 0:
            self.protocol = url_parts.scheme.lower()

        if len(url_parts.netloc) > 0:
            self.domain = url_parts.netloc.lower()

        if len(url_parts.path) > 0:
            self.path = url_parts.path
            self.extension = os.path.splitext(url_parts.path)[1][1:].lower()

        if len(url_parts.query) == 0:
            self.query = ''
        else:
            qsin = urllib.parse.parse_qs(url_parts.query, keep_blank_values=True)
            # URL's with querystring parameters in different order are equivalent
            qsout = dict_to_sorted_list(qsin)
            self.query = urllib.parse.urlencode(qsout)

    @property
    def url(self):
        return str(self)

    @url.setter
    def url(self, value):
        self._set_url(value)

    @property
    def referrer(self):
        return self._referrer

    @referrer.setter
    def referrer(self, value):
        self_referrer = value
        self._set_url(str(self))

    @referrer.deleter
    def referrer(self):
        del self._referrer

    @property
    def verb(self):
        if len(self._post_data) > 0:
            return 'POST'
        elif len(self._verb) > 0:
            return self._verb.upper()
        else:
            return 'GET'

    @verb.setter
    def verb(self, value):
        if value.upper() in ['GET', 'POST', 'HEAD', '']:
            self._verb = value.upper()

    @verb.deleter
    def verb(self):
        del self._verb

    @property
    def post_data(self):
        return self._post_data

    @post_data.setter
    def post_data(self, post_data):
        self._post_data = []
        keys = [x for x, y in post_data]
        keys.sort()
        for k in keys:
            for v in [v for v in post_data if v[0] == k]:
                self._post_data.append((k, v[1]))

    def post_data_string(self):
        if self.encoding == 'multipart/form-data':
            if not self.boundary:
                self.boundary = uuid.uuid4().hex

            # Adapted from: http://code.activestate.com/recipes/146306-http-client-to-post-using-multipartform-data/
            dat = []
            for key, value in self._post_data:
                dat.append('--' + self.boundary)
                dat.append('Content-Disposition: form-data; name="{0}"'.format(key))
                dat.append('')
                dat.append(value)
            dat.append('--' + self.boundary + '--')
            dat.append('')

            return r'\r\n'.join(dat)
        else:
            return urllib.parse.urlencode(self._post_data)

    def __str__(self):
        if len(self.domain) > 0:
            url = '{0}://{1}{2}'.format(self.protocol, self.domain, self.path)
        else:
            url = self.path
        if len(self.query) > 0:
            url += '?' + self.query
        return url

    def hash(self):
        # Relies on query, post and headers being sorted
        h = [self._verb, self.__str__()]

        hdrs = dict_to_sorted_list(self.headers)
        if len(hdrs) > 0:
            h.append(urllib.parse.urlencode(hdrs))

        pd = self.post_data_string()
        if len(pd) > 0:
            h.append(pd)

        return hashlib.sha1(''.join(h).encode()).hexdigest()


class Response(object):
    def __init__(self, response, start_time):
        end_time = time.time()
        self.headers = response.getheaders()
        html = self.get_header('content-type').startswith('text/html')
        temp = response.read()
        if temp and html:
            self.content = temp.decode('utf-8', errors='replace')
        elif temp:
            self.content = temp
        else:
            self.content = ''
        self.time = end_time - start_time
        self.status = response.status
        self.message = response.reason
        self.version = response.version
        if html and len(self.content) > 0:
            self.is_html = True
        else:
            self.is_html = False

    def get_header(self, name):
        hdrs = self.get_headers(name)
        if len(hdrs) > 0:
            return hdrs[0]
        else:
            return ''

    def get_headers(self, name):
        hdrs = [h for h in self.headers if h[0].lower() == name.lower()]
        return [h[1] for h in hdrs]


class RequestQueue(queue.Queue):
    def __init__(self, session):
        super(RequestQueue, self).__init__()
        self.session = session
        self._lock = threading.Lock()
        self.requests = set()
        self.urls = set()

    def _validate(self, request):
        if request is None:
            return False

        if request.protocol is None or len(request.protocol) == 0 or \
                request.domain is None or len(request.domain) == 0:

            parts = urllib.parse.urlparse(self.session.domain)

            if len(request.protocol) == 0:
                request.protocol = parts.scheme.lower()

            if len(request.domain) == 0:
                request.domain = parts.netloc.lower()

            request.path = parts.path + request.path

        for ignore in self.session.ignore_url:
            # TODO: Should this be == rather than endswith?
            if request.path.lower().endswith(ignore.lower()):
                return False

        if request.extension in self.session.ignore_ext:
            return False

        # url = str(request)
        # if len(url) == 0:
            # return False
        if request.path.startswith('#'):
            return False

        if re.match('^http', request.protocol, re.IGNORECASE):
            return True
        else:
            return False

    def _put_request(self, request, block, timeout):
        if self._validate(request):
            hc = request.hash()
            if (not hc in self.requests) and (len(self.urls) < self.session.max_requests or self.session.max_requests == 0):
                self.requests.add(hc)
                self.urls.add(str(request))
                queue.Queue.put(self, request, block, timeout)
            elif request.redirects > 0:
                # Continue to test for looping redirects
                request.verb = 'HEAD'
                queue.Queue.put(self, request, block, timeout)

    def _put_url(self, source, url, referrer, block, timeout):
        req = Request(url, referrer=referrer)
        req.source = source
        self._put_request(req, block, timeout)

    def put_url(self, source, url, referrer, block=True, timeout=None):
        with self._lock:
            if isinstance(url, list):
                for u in url:
                    self._put_url(source, str(u), referrer, block, timeout)
            else:
                self._put_url(source, str(url), referrer, block, timeout)

    def put(self, request, block=True, timeout=None):
        with self._lock:
            self._put_request(request, block, timeout)

    def load(self, requests, urls, pending, block=True, timeout=None):
        with self._lock:
            self.requests = requests
            self.urls = urls
            for r in pending:
                queue.Queue.put(self, r, block, timeout)

    def save(self, block=False):
        with self._lock:
            rq = []
            while not self.empty():
                rq.append(self.get(block))
            return self.requests, self.urls, rq

    def retry(self, request):
        if request.timeouts >= self.session.max_retries:
            return False
        elif self._validate(request):
            request.timeouts += 1
            queue.Queue.put(self, request)
            return True

    def redirect(self, request, url):
        if request.redirects >= self.session.max_redirects:
            return False, ['Max redirects exceeded', 'Original referrer: {0}'.format(request.referrer)]
        else:
            req = copy.copy(request)
            req.referrer = str(request)
            req.url = url

            if str(req) == str(request):
                return False, ['Page redirects to itself']
            else:
                if req.redirects == 0:
                    # Reset to get on redirect
                    req.post_data = []
                    req.verb = ''

                req.redirects += 1

                with self._lock:
                    self._put_request(req, True, None)

                return True, []


class HtmlHelper(object):
    # From: http://effbot.org/zone/re-sub.htm#unescape-html
    def html_decode(text):
        def fixup(m):
            text = m.group(0)
            if text[:2] == "&#":
                try:
                    if text[:3] == "&#x":
                        return chr(int(text[3:-1], 16))
                    else:
                        return chr(int(text[2:-1]))
                except ValueError:
                    pass
            else:
                try:
                    text = chr(html.entities.name2codepoint[text[1:-1]])
                except KeyError:
                    pass
            return text
        return re.sub("&#?\w+;", fixup, text)

    def __init__(self, document):
        self.document = document
        self.flags = re.IGNORECASE | re.DOTALL

    def _element_expression(self, elements):
        if type(elements) is str:
            return elements
        elif type(elements) is list or type(elements) is tuple:
            return '|'.join(elements)

    def get_elements(self, elements):
        e = self._element_expression(elements)
        rx = re.compile(r'(?:<\s*(?P<element>{0})\b[^>/]*)(?:(?:/\s*>)|(?:>.*?<\s*/\s*(?P=element)\s*>))'.format(e), self.flags)
        mtchs = rx.finditer(self.document)
        for m in mtchs:
            yield HtmlHelper(m.group(0))

    def get_attribute(self, attribute, elements=None):
        # Test strings:
        # < form name = name action = test 1 method = get>
        # < form name = "name" action = "test 1" method = "get">
        # < form name = 'name' action = 'test 1' method = 'get'>
        if elements:
            e = self._element_expression(elements)
            rx = re.compile(r'''<\s*(?P<element>{0})\s[^>]*?(?<=\s){1}\s*=\s*(?P<quoted>"|')?(?P<attr>.*?)(?(quoted)(?P=quoted)|[\s>])''' \
                .format(e, attribute), self.flags)
        else:
            rx = re.compile(r'''<\s*(?P<element>[^\s>]+)\s[^>]*?(?<=\s){0}\s*=\s*(?P<quoted>"|')?(?P<attr>.*?)(?(quoted)(?P=quoted)|[\s>])''' \
                .format(attribute), self.flags)

        mtchs = rx.finditer(self.document)
        for m in mtchs:
            yield (m.group('element'), attribute, m.group('attr'))

    def get_text(self, elements=None):
        if elements:
            # rx = re.compile(r'<\s*{0}\b[^>]*?>(?P<text>[^<]*?\w[^<]*?)(?:<|$)'.format(element), self.flags)
            for e in self.get_elements(elements):
                e.strip_elements()
                yield e.document
        else:
            rx = re.compile(r'(?:^[^<]|>)(?P<text>[^<]*?\w[^<]*?)(?:<|$)', self.flags)

            mtchs = rx.finditer(self.document)
            for m in mtchs:
                yield m.group('text')

    def strip_elements(self, elements=None):
        if elements:
            e = self._element_expression(elements)
            self.document = re.sub(r'<\s*(?P<element>{0})\b.*?>.*?<\s*/\s*(?P=element)\s*>'.format(e), \
                '', self.document, flags=self.flags)
        else:
            self.document = re.sub(r'<.*?>', '', self.document, flags=self.flags)

    def strip_comments(self):
        self.document = re.sub(r'<\s*!\s*-\s*-.*?-\s*-\s*>', '', self.document, flags=self.flags)

    def get_comments(self):
        rx = re.compile(r'<\s*!\s*-\s*-(?P<comment>.*?)-\s*-\s*>', self.flags)

        mtchs = rx.finditer(self.document)
        for m in mtchs:
            yield m.group('comment')


class TextHelper(object):
    SENTENCE_END = '!?.'

    def __init__(self, document=''):
        self.items = []
        self.text = None
        if document and len(document) > 0:
            self.append(document)

    def append(self, text):
        self.text = None
        if len(text.strip()) > 0:
            temp = text.strip().lower()
            if temp[-1] in TextHelper.SENTENCE_END:
                temp += ' '
            else:
                temp += '. '

            self.items.append(temp)

    def sentence_count(self):
        s = 0
        for se in TextHelper.SENTENCE_END:
            s += self._to_s().count(se)

        if s == 0:
            s = 1

        return s

    def word_count(self):
        return len(self._to_s().split(' '))

    def syllable_count(self):
        s = 0
        for word in self._to_s().split(' '):
            w = re.sub('\W', '', word)
            if len(w) <= 3:
                s += 1
            else:
                w = re.sub('(?:es|ed|[^l]e)$', '', w, re.IGNORECASE)
                s += len(re.findall('[aeiouy]{1,2}', w, re.IGNORECASE))
                s += len(re.findall('eo|ia|ie|io|iu|ua|ui|uo', w, re.IGNORECASE))

        if s == 0:
            s = 1

        return s

    def get_sentences(self):
        for s in re.split('[{0}]'.format(TextHelper.SENTENCE_END), self._to_s(), re.IGNORECASE | re.DOTALL):
            if len(s) > 0:
                yield s

    def get_words(self):
        for w in self._to_s().split(' '):
            yield w

    def _to_s(self):
        if not self.text:
            self.text = ''.join(self.items)

        return self.text

    def __str__(self):
        return self._to_s()

    def __len__(self):
        return len(self._to_s())

# module.initialise is called every time module is created
# module.begin is called the first time module is started (not on resume)
# module.resume is called when the module is resumed
# module.end is called when end is requested
# module.complete is called when end is completed


class ModuleBase(object):
    def __init__(self):
        self.name = self.__class__.__name__
        self.source = self.__class__.__name__.lower()
        self.sitecheck = None
        self.sync_lock = None

    def initialise(self, sitecheck):
        self.sitecheck = sitecheck
        self.sync_lock = threading.Lock()

    def _add_request(self, url, referrer):
        self.sitecheck.request_queue.put_url(self.name, url, referrer)

    def _create_request(self, url, referrer):
        req = Request(url, referrer=referrer)
        req.source = self.name
        return req

    def __getstate__(self):
        state = dict(self.__dict__)
        return self._clean_state(state)

    def _clean_state(self, state):
        del state['sync_lock']
        del state['sitecheck']
        return state


class Authenticate(ModuleBase):
    AUTH_META_KEY = '__AUTHENTICATION'
    LOGIN = 'Login'
    LOGOUT = 'Logout'

    def __init__(self, login=[], logout=[]):
        super(Authenticate, self).__init__()
        self.login = login
        self.logout = logout

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
