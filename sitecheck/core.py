# -*- coding: utf-8 -*-

# Copyright 2009-2011 Andrew Kershaw

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
import urllib.request, urllib.parse, urllib.error
import http.cookies
import socket
import queue
import datetime
import urllib.parse
import re
import hashlib
import uuid
import pickle

from sitecheck.utils import append

class SessionNotSetException(Exception):
	pass

class SessionNotSetException(Exception):
	pass

class SiteCheckStartedException(Exception):
	pass

class SiteCheck(object):
	def __init__(self):
		self.session = None
		self.output_queue = OutputQueue()
		self.request_queue = None

		self._started = False
		self._resume = False
		self._threads = []
		self._log_writer = None

	def set_session(self, session):
		if self._started: raise SiteCheckStartedException()

		self.session = session
		self.request_queue = RequestQueue(session)

	def resume(self, suspend_file):
		if self._started: raise SiteCheckStartedException()

		f = open(suspend_file, 'r')
		sd = pickle.load(f)
		f.close()

		self.session = sd[0]
		self.request_queue = RequestQueue(sd[0])
		self.request_queue.load(sd[1], sd[2])

		self._resume = True

	def is_complete(self):
		if self.session == None: raise SessionNotSetException()

		cmpl = False
		if self.request_queue.empty():
			cmpl = True
			for t in self._threads:
				if t.active:
					cmpl = False

		return cmpl

	def begin(self):
		if self.session == None: raise SessionNotSetException()
		if self._started: raise SiteCheckStartedException()

		self._started = True

		if not self.session.domain[-1] == '/' and len(os.path.splitext(self.session.domain)[1]) == 0:
			self.session.domain = self.session.domain + '/'

		append(self.session.output, os.sep)
		append(self.session._config, os.sep)
		
		if len(urllib.parse.urlparse(self.session.domain).netloc) == 0: raise Exception('Invalid domain')

		# Organise file type sets
		self.session.include_ext = self.session.include_ext.difference(self.session.ignore_ext)
		self.session.test_ext = self.session.test_ext.difference(self.session.ignore_ext.union(self.session.include_ext))

		# Start logging thread
		self._log_writer = LogWriter(self)
		self._log_writer.setDaemon(True)
		self._log_writer.start()

		# Initialise modules
		for m in range(len(self.session.modules)):
			mod = self.session.modules[m]
			try:
				if not hasattr(mod, 'process'): raise Exception('Process method not defined')

				mod.initialise(self)

				if self._resume:
					if hasattr(mod, 'resume'): mod.resume()
				else:
					if hasattr(mod, 'begin'): mod.begin()
			except:
				if hasattr(mod, 'name'):
					self.output_queue.put(mod.log_file, 'ERROR: ' + str(sys.exc_info()))
				else:
					# If intialise fails, log_file is not populated
					self.output_queue.put(None, 'ERROR: ' + str(sys.exc_info()))
				self.session.modules.pop(m)

		# Create worker thread pool
		for i in range(self.session.thread_pool):
			thread = Checker(self)
			thread.setDaemon(True)
			thread.start()
			self._threads.append(thread)

		# Add initial URL to queue
		a = self.session.authenticate
		if a.login_url == None or len(a.login_url) == 0:
			self.request_queue.put_url('', self.session.page, self.session.domain)
		else:
			# Authenticate before spidering begins
			if not a.logout_url == None:
				if not a.logout_url in self.session.ignore_url: self.session.ignore_url.append(a.logout_url)

			r = Request(Authenticate.AUTH_REQUEST_KEY, a.login_url, self.session.domain)
			a = Authenticate()
			a.initialise(self)
			r.modules = [a]
			self.request_queue.put(r)

	def _stop_threads(self):
		if self.session == None: raise SessionNotSetException()

		# Wait for worker threads to complete
		Checker.terminate.set()
		for thread in self._threads:
			thread.join()

	def _flush_logs(self):
		if self.session == None: raise SessionNotSetException()

		# Wait for log entries to be written
		LogWriter.terminate.set()
		self._log_writer.join()

	def end(self):
		if self.session == None: raise SessionNotSetException()

		self._stop_threads()

		for mod in self.session.modules:
			if hasattr(mod, 'complete'): mod.complete()

		self._flush_logs()

	def suspend(self, suspend_file):
		if self.session == None: raise SessionNotSetException()

		self._stop_threads()

		for mod in self.session.modules:
			if hasattr(mod, 'suspend'): mod.suspend()

		self._flush_logs()

		dat = self.request_queue.save()
		fl = open(suspend_file, 'w')
		# Dump config, url's and requests to file
		pickle.dump((self.session, dat[0], dat[1]), fl)
		fl.close()

class LogWriter(threading.Thread):
	terminate = threading.Event()

	def __init__(self, sitecheck):
		threading.Thread.__init__(self)
		self.sitecheck = sitecheck
		self._session = sitecheck.session
		self._output_queue = sitecheck.output_queue
		self._outfiles = {}
		self.default_log_file = 'sitecheck'
		self.extension = '.log'

	def _write_next(self):
		try:
			fl, msg = self._output_queue.get(block=False)
		except queue.Empty:
			LogWriter.terminate.wait(self._session.wait_seconds)
		else:
			if fl == None: fl = self.default_log_file
			if not fl in self._outfiles:
				self._outfiles[fl] = open('{}{}{}{}'.format(self._session.output, os.sep, fl, self.extension), mode='w')
			self._outfiles[fl].write(msg)
			self._outfiles[fl].write('\n')

	def run(self):
		log = open('{}{}{}{}'.format(self._session.output, os.sep, self.default_log_file, self.extension), mode='w')
		self._outfiles = {self.default_log_file: log}

		log.write('Started: {}\n\n'.format(datetime.datetime.now()))

		while not LogWriter.terminate.isSet():
			self._write_next()

		log.write('Completed: {}\n\n'.format(datetime.datetime.now()))

		while not self._output_queue.empty():
			self._write_next()

		for fl in self._outfiles.items():
			fl[1].close()

class Checker(threading.Thread):
	terminate = threading.Event()

	def __init__(self, sitecheck):
		threading.Thread.__init__(self)
		self.active = False # For determining whether a request is in progress
		self.sitecheck = sitecheck
		self._session = sitecheck.session
		self._output_queue = sitecheck.output_queue
		self._request_queue = sitecheck.request_queue

	def set_verb(self, request):
		if len(request.verb) == 0:
			dom = urllib.parse.urlparse(self._session.domain)
			if not request.domain == dom.netloc:
				# External domain
				request.verb = 'HEAD'
			elif not request.path.startswith(dom.path) and not request.extension in self._session.include_ext:
				# This is hit if path is a file on the current domain but above the current path
				request.verb = 'HEAD'
			elif request.extension in self._session.test_ext:
				request.verb = 'HEAD'
			else:
				request.set_verb()

	def set_headers(self, request):
		hdrs = self._session.headers.copy()
		request.headers.update(hdrs)
		if 'Content-Type' in request.headers or 'content-type' in request.headers:
			pass
		else:
			request.headers['Content-Type'] = request.encoding

	def set_cookie(self, request):
		if hasattr(self._session, '_cookie'):
			c = self._session._cookie.output(['key', 'coded_value'], '', ';').strip()
			if 'Cookie' in request.headers:
				request.headers['Cookie'] += c
			elif 'cookie' in request.headers:
				request.headers['cookie'] += c
			else:
				request.headers['Cookie'] = c

	def get_cookie(self, response):
		cookies = response.get_headers('set-cookie')
		if len(cookies) > 0:
			if not hasattr(self._session, '_cookie'): self._session._cookie = http.cookies.SimpleCookie()
			for c in cookies:
				self._session._cookie.load(c)

	def process(self, request, response):
		if len(request.modules) == 0: request.modules = self._session.modules
		for mod in request.modules:
			try:
				mod.process(request, response)
			except:
				ex = sys.exc_info()
				self._output_queue.put(mod.log_file, 'ERROR: Processing with module [{}]\n{}'.format(mod.name, str(ex[1])))

	def fetch(self, request):
		full_path = request.path
		if len(request.query) > 0: full_path += '?' + request.query

		if request.protocol == 'https':
			c = http.client.HTTPSConnection(request.domain, timeout=self._session.request_timeout)
		elif request.protocol == 'http':
			c = http.client.HTTPConnection(request.domain, timeout=self._session.request_timeout)
		else:
			raise Exception('Unrecognised protocol: {}'.format(request.protocol))

		res = err = None
		try:
			c.connect()
			st = time.time()
			c.request(request.verb, full_path, request.get_post_data(), request.headers)
			r = c.getresponse()
			res = Response(r, st)
		except socket.gaierror:
			ex = sys.exc_info()
			err = 'DNS error {} {}'.format(str(ex[0]), str(ex[1])) # Probably
		except socket.timeout:
			ex = sys.exc_info()
			err = 'Timeout {} {}'.format(str(ex[0]), str(ex[1]))
		except http.client.IncompleteRead:
			ex = sys.exc_info()
			err = 'Read error {} {}'.format(str(ex[0]), str(ex[1]))
		except:
			ex = sys.exc_info()
			err = 'Error {} {}'.format(str(ex[0]), str(ex[1]))
		finally:
			c.close()

		return res, err

	def run(self):
		while not Checker.terminate.isSet():
			Checker.terminate.wait(self._session.wait_seconds)
			try:
				req = self._request_queue.get(block=False)
			except queue.Empty:
				self.active = False
			else:
				self.active = True

				self.set_verb(req)
				self.set_headers(req)
				self.set_cookie(req)

				res, err = self.fetch(req)

				msgs = []

				if res:
					dom = urllib.parse.urlparse(self._session.domain)
					if req.domain == dom.netloc: self.get_cookie(res)

					msgs.append('{}: [{}] status: {}'.format(req.verb, str(req), str(res.status)))
					if self._session.log.request_headers: msgs.append('\tREQUEST HEADERS: {}'.format(req.headers))
					if self._session.log.post_data and len(req.postdata) > 0: msgs.append('\tPOST DATA: {}'.format(req.get_post_data()))
					if self._session.log.response_headers: msgs.append('\tRESPONSE HEADERS: {}'.format(res.headers))

					if (res.status >= 300 and res.status < 400) and req.domain == dom.netloc:
						loc = res.get_headers('location')
						if len(loc) > 0:
							req.redirect(loc[-1])
							if len(loc) > 1:
								msgs.append('\tERROR: Multiple redirect locations found: [{}]'.format(loc))
								msgs.append('\t\tURL: [{}]'.format(str(req)))
							if req.redirects > self._session.max_redirects:
								msgs.append('\tERROR: Exceeded {} redirects for: [{}]'.format(self._session.max_redirects, req.referrer))
							else:
								self._request_queue.put(req)
						else:
							msgs.append('\tERROR: Redirect with no location: [{}]'.format(req.referrer))

					if res.time > self._session.slow_request:
						msgs.append('\tSLOW REQUEST: [{}] ({:.3f} seconds)'.format(str(req), res.time))

					self.process(req, res)
				else:
					msgs.append('{}: [{}]'.format(req.verb, str(req)))
					if err:
						msgs.append('\tERROR: [{}] {}'.format(str(req), err))
					if not self._request_queue.retry(req):
						msgs.append('\tERROR: Exceeded max_retries for: [{}]'.format(str(req)))

				msgs[-1] += '\n'

				self._output_queue.put(None, msgs)

class Request(object):
	def __init__(self, source, url, referrer, encoding='application/x-www-form-urlencoded'):
		self.source = source
		self.referrer = referrer
		self.encoding = encoding
		self.boundary = uuid.uuid4().hex
		self.verb = '' # Do not default to GET so we can tell if it is set manually or not
		self.redirects = 0
		self.timeouts = 0
		self.modules = []
		self.postdata = []
		self.headers = {} # Dictionary for httplib
		self._set_url(url)

	def _set_url(self, url):
		url = url.replace(' ', '%20')
		url_parts = urllib.parse.urlparse(url)

		if len(url_parts.scheme) == 0:
			# Relative URL - join with referrer
			url = urllib.parse.urljoin(self.referrer, url)
			url_parts = urllib.parse.urlparse(url)

		self.protocol = url_parts.scheme.lower()
		self.domain = url_parts.netloc.lower()
		self.path = url_parts.path
		self.extension = os.path.splitext(url_parts.path)[1][1:].lower()

		if len(url_parts.query) == 0:
			self.query = ''
		else:
			qsin = urllib.parse.parse_qs(url_parts.query, keep_blank_values=True)
			qsout = []
			keys = list(qsin.keys())
			keys.sort() # URL's with querystring parameters in different order are equivalent
			for k in keys:
				qsout.append((k, qsin[k][0]))
			self.query = urllib.parse.urlencode(qsout)

	def get_post_data(self):
		if self.encoding == 'multipart/form-data':
			# Adapted from: http://code.activestate.com/recipes/146306-http-client-to-post-using-multipartform-data/
			dat = []
			for key, value in self.postdata:
				dat.append('--' + self.boundary)
				dat.append('Content-Disposition: form-data; name="{}"'.format(key))
				dat.append('')
				dat.append(value)
			dat.append('--' + self.boundary + '--')
			dat.append('')
			return r'\r\n'.join(dat)
		else:
			return urllib.parse.urlencode(self.postdata)

	def set_post_data(self, postdata):
		self.postdata = []
		keys = [x for x, y in postdata]
		keys.sort()
		for k in keys:
			for v in [v for v in postdata if v[0] == k]:
				self.postdata.append((k, v[1]))

	def __str__(self):
		url = '{}://{}{}'.format(self.protocol, self.domain, self.path)
		#if len(self.parameters) > 0: url += ';' + self.parameters
		if len(self.query) > 0: url += '?' + self.query
		return url

	def hash(self):
		# Relies on query and post being sorted
		m = hashlib.sha1()
		m.update(self.verb.encode())
		m.update(self.__str__().encode())
		pd = self.get_post_data()
		if len(pd) > 0: m.update(pd.encode())
		return m.hexdigest()

	def redirect(self, url):
		if self.redirects == 0:
			self.referrer = self.__str__()
		self._set_url(url)
		self.redirects += 1

	def set_verb(self):
		if len(self.get_post_data()) > 0:
			self.verb = 'POST'
		else:
			self.verb = 'GET'

class Response(object):
	def __init__(self, response, start_time):
		end_time = time.time()
		self.headers = response.getheaders()
		html = self.get_header('content-type').startswith('text/html')
		temp = response.read()
		if temp:
			self.content = temp.decode('utf-8', errors='replace')
		else:
			self.content = ''
		self.time = end_time - start_time
		self.status = response.status
		self.message = response.reason
		self.version = response.version
		if self.status < 300 and html and len(self.content) > 0:
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
		queue.Queue.__init__(self)
		self.session = session
		self._url_lock = threading.Lock()
		self.urls = {}

	def is_valid(self, url):
		if url == None: return False
		if len(url) == 0: return False
		if url.startswith('#') or url.lower() in self.session.ignore_protocol: return False

		parts = urllib.parse.urlparse(url)
		for ignore in self.session.ignore_url:
			if parts.path.lower().endswith(ignore.lower()): return False

		ext = os.path.splitext(parts.path)[1][1:].lower()
		if ext in self.session.ignore_ext: return False

		if re.match('^http', parts.scheme, re.IGNORECASE) or len(parts.scheme) == 0:
			return True
		else:
			return False

	def _put_url(self, source, url, referrer, block, timeout):
		req = Request(source, url, referrer)
		if self.is_valid(str(req)):
			hc = req.hash()
			if not hc in self.urls:
				self.urls[hc] = True
				queue.Queue.put(self, req, block, timeout)

	def put_url(self, source, url, referrer, block=True, timeout=None):
		with self._url_lock:
			if isinstance(url, list):
				for u in url:
					self._put_url(source, u, referrer, block, timeout)
			else:
				self._put_url(source, str(url), referrer, block, timeout)

	def put(self, request, block=True, timeout=None):
		if self.is_valid(str(request)):
			with self._url_lock:
				hc = request.hash()
				if not hc in self.urls:
					self.urls[hc] = True
					queue.Queue.put(self, request, block, timeout)

	def load(self, urls, requests, block=True, timeout=None):
		self.urls = urls
		for r in requests:
			queue.Queue.put(self, r, block, timeout)

	def save(self, block=False):
		rq = []
		while not self.empty():
			rq.append(self.get(block))
		return (self.urls, rq)

	def retry(self, request):
		if request.timeouts >= self.session.max_retries:
			return False
		else:
			request.timeouts += 1
			queue.Queue.put(self, request)
			return True

class OutputQueue(queue.Queue):
	def __init__(self):
		queue.Queue.__init__(self)

	def put(self, file_name, value, block=True, timeout=None):
		if isinstance(value, list):
			for val in value:
				queue.Queue.put(self, (file_name, val), block, timeout)
		else:
			queue.Queue.put(self, (file_name, str(value)), block, timeout)

class HtmlHelper(object):
	def __init__(self, document):
		self.document = document
		self.flags = re.IGNORECASE | re.DOTALL # | re.MULTILINE

	def get_element(self, element):
		#rx = re.compile(r'<\s*%s\b.*?>' % element, self.flags)
		rx = re.compile(r'<\s*{}\b[^>]*(?:/\s*>)|(?:>.*?<\s*/\s*{}\s*>)'.format(element, element), self.flags)
		mtchs = rx.finditer(self.document)
		for m in mtchs:
			yield HtmlHelper(m.group(0))

	def get_attribute(self, attribute, element=None):
		# Test strings:
		# < form name = name action = test 1 method = get>
		# < form name = "name" action = "test 1" method = "get">

		if element:
			rx = re.compile(r'<\s*(?P<element>{})\s[^>]*?(?<=\s){}\s*=\s*(?P<quoted>")?(?P<attr>.*?)(?(quoted)"|[\s>])' \
				.format(element, attribute), self.flags)
		else:
			rx = re.compile(r'<\s*(?P<element>[^\s>]+)\s[^>]*?(?<=\s){}\s*=\s*(?P<quoted>")?(?P<attr>.*?)(?(quoted)"|[\s>])' \
				.format(attribute), self.flags)

		mtchs = rx.finditer(self.document)
		for m in mtchs:
			yield (m.group('element'), attribute, m.group('attr'))

	def get_text(self, element=None):
		if element:
			rx = re.compile(r'<\s*%s\b[^>]*?>(?P<text>[^<]+?\w[^<]+?)(?:<|$)' % element, self.flags)
		else:
			rx = re.compile(r'(?:^[^<]|>)(?P<text>[^<]+?\w[^<]+?)(?:<|$)', self.flags)

		mtchs = rx.finditer(self.document)
		for m in mtchs:
			yield m.group('text')

	def strip_element(self, elements):
		names = elements
		if type(elements) is str:
			names = (elements)

		for e in names:
			self.document = re.sub(r'<\s*{}\b.*?>.*?<\s*/\s*{}\s*>'.format(e, e), \
				'', self.document, flags=self.flags)

	def strip_comments(self):
		self.document = re.sub(r'<\s*!\s*-\s*-.*?-\s*-\s*>', '', self.document, flags=self.flags)

	def get_comments(self):
		rx = re.compile(r'<\s*!\s*-\s*-(?P<comment>.*?)-\s*-\s*>', self.flags)

		mtchs = rx.finditer(self.document)
		for m in mtchs:
			yield m.group('comment')

class MessageBatch(object):
	def __init__(self, log_file):
		self.log_file = log_file
		self.header = None
		self.messages = []

	def set_header(self, message, log_file=None):
		if log_file == None: log_file = self.log_file
		self.header = (log_file, message)

	def add(self, message, log_file=None):
		if log_file == None: log_file = self.log_file
		if isinstance(message, list):
			self.messages.extend([(log_file, m) for m in message])
		else:
			self.messages.append((log_file, str(message)))

	def __len__(self):
		return len(self.messages)

def message_batch(method):
	def inner(self, *args, **kwargs):
		mb = MessageBatch(self.log_file)
		try:
			return method(self, mb, *args, **kwargs)
		finally:
			if len(mb.messages) > 0 and mb.header:
				self.sitecheck.output_queue.put(*mb.header)

			for m in mb.messages:
				self.sitecheck.output_queue.put(*m)

	return inner

class ModuleBase(object):
	def initialise(self, sitecheck):
		self.sitecheck = sitecheck
		self.name = self.__class__.__name__
		self.log_file = self.__class__.__name__.lower()
		self.sync_lock = threading.Lock()

	def add_message(self, message, log_file=None):
		if log_file == None: log_file = self.log_file
		self.sitecheck.output_queue.put(log_file, message)

	def add_request(self, url, referrer):
		self.sitecheck.request_queue.put_url(self.name, url, referrer)

	def __getstate__(self):
		state = dict(self.__dict__)
		return self._clean_state(state)

	def _clean_state(self, state):
		del state['sync_lock']
		del state['sitecheck']
		return state

	#def __setstate__(self, state):
		 #self.__dict__.update(state)

class Authenticate(ModuleBase):
	AUTH_REQUEST_KEY = '__AUTHENTICATION__REQ'
	AUTH_RESPONSE_KEY = '__AUTHENTICATION__RES'

	def process(self, request, response):
		a = self.sitecheck.session.authenticate
		if request.source == Authenticate.AUTH_REQUEST_KEY:
			self.add_message('Authenticating {}: [{}] status: {}'.format(request.verb, str(request), str(response.status)))

			if a.post:
				url = a.login_url
			else:
				if len(urllib.parse.urlparse(a.login_url).query) > 0:
					sep = '&'
				else:
					sep = '?'
				url = '{}{}{}'.format(a.login_url, sep, urllib.parse.urlencode(a.params, True))

			r = Request(Authenticate.AUTH_RESPONSE_KEY, url, str(request))
			if a.post: r.set_post_data(a.params)
			r.modules = [self]
			self.sitecheck.request_queue.put(r)
		elif request.source == Authenticate.AUTH_RESPONSE_KEY:
			self.add_message('Response {}: [{}] status: {}'.format(request.verb, str(request), str(response.status)))
			# Begin spidering
			self.sitecheck.request_queue.put_url('', self.sitecheck.session.page, self.sitecheck.session.domain)
