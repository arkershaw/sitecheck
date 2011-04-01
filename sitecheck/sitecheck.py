#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Copyright 2009 Andrew Kershaw

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

import sys, os, threading, time, httplib, urllib, socket, Queue, datetime, urlparse, re, codecs
import sc_module

AUTH_REQUEST_KEY = '__AUTHENTICATION__REQ'
AUTH_RESPONSE_KEY = '__AUTHENTICATION__RES'

#import urllib2
#class HeadRequest(urllib2.Request):
#	def get_method(self):
#		return "HEAD"

#proxy_handler = urllib2.ProxyHandler({'http': 'http://www.example.com:3128/'})
#proxy_auth_handler = urllib2.ProxyBasicAuthHandler()
#proxy_auth_handler.add_password('realm', 'host', 'username', 'password')
#opener = urllib2.build_opener(proxy_handler, proxy_auth_handler)
#urllib2.install_opener(opener)
#opener.addheaders = [('User-agent', 'Mozilla/5.0')]

#response = urllib2.urlopen(HeadRequest("http://google.com/index.html"))
#Headers are available via response.info() as before. Interestingly, you can 
#find the URL that you were redirected to:
#print response.geturl()

class LogWriter(threading.Thread):
	def __init__(self, terminate):
		threading.Thread.__init__(self)
		self.terminate = terminate
		self.outfiles = {}
	
	def writenext(self):
		try:
			mod, out = sc_module.OutputQueue.get(block=False)
		except Queue.Empty:
			self.terminate.wait(sc_module.session.wait_seconds)
		else:
			if mod in self.outfiles:
				self.outfiles[mod].write(out)
				self.outfiles[mod].write('\n')
			else:
				self.outfiles['sitecheck'].write('Module output file not found: [%s]\n' % mod)

	def run(self):
		sc_module.ensure_dir(sc_module.session.output)
		self.outfiles = {'sitecheck': codecs.open('%s%ssitecheck.log' % (sc_module.session.output, os.sep), mode='a', encoding='utf8', errors='replace')}
		for name in sc_module.session.modules.iterkeys():
			self.outfiles[name] = codecs.open('%s%s%s.log' % (sc_module.session.output, os.sep, name), mode='a', encoding='utf8', errors='replace')

		sc_module.OutputQueue.put(None, 'Started: %s\n' % str(datetime.datetime.now()))

		while not self.terminate.isSet():
			self.writenext()

		sc_module.OutputQueue.put(None, 'Completed: %s\n' % str(datetime.datetime.now()))

		while not sc_module.OutputQueue.empty():
			self.writenext()

		for fl in self.outfiles.iteritems():
			fl[1].close()

class SiteChecker(threading.Thread):
	def __init__(self, terminate):
		threading.Thread.__init__(self)
		self.active = False
		self.terminate = terminate

	def _fetch(self, url, verb='GET', postdata=[], headers={}):
		full_path = url.path
		if len(url.query) > 0: full_path += '?' + url.query
		full_url = url.scheme + '://' + url.netloc + full_path
		
		if url.scheme == 'https':
			c = httplib.HTTPSConnection(url.netloc)
		else:
			c = httplib.HTTPConnection(url.netloc)
		res = err = None
		try:
			c.connect()
			c.sock.settimeout(sc_module.session.request_timeout) #TODO: This does not seem to work
			st = time.time()
			c.request(verb, full_path, urllib.urlencode(postdata), headers)
			r = c.getresponse()
			res = sc_module.Response(r, st)
		except socket.gaierror:
			ex = sys.exc_info()
			err = 'DNS error %s %s' % (str(ex[0]), str(ex[1])) # Probably
		except socket.timeout:
			ex = sys.exc_info()
			err = 'Timeout %s %s' % (str(ex[0]), str(ex[1]))
		except httplib.IncompleteRead:
			ex = sys.exc_info()
			err = 'Read error %s %s' % (str(ex[0]), str(ex[1]))
		except:
			ex = sys.exc_info()
			err = 'Error %s %s' % (str(ex[0]), str(ex[1]))
		finally:
			c.close()

		return res, err

	def run(self):
		while not self.terminate.isSet():
			self.terminate.wait(sc_module.session.wait_seconds)
			try:
				request = sc_module.RequestQueue.get(block=False)
			except Queue.Empty:
				self.active = False
			else:
				self.active = True
				url = request.url

				if len(request.verb) == 0:
					sp = urlparse.urlparse(sc_module.session.path).path
					ext = os.path.splitext(url.path)[1][1:].lower()
					if not url.netloc == sc_module.session.domain:
						# External domain
						request.verb = 'HEAD'
					elif not url.path.startswith(sp) and not ext in sc_module.session.include_ext:
						# This is hit if path is a file
						request.verb = 'HEAD'
					elif ext in sc_module.session.test_ext:
						request.verb = 'HEAD'
					elif len(request.postdata) > 0:
						request.verb = 'POST'
					else:
						request.verb = 'GET'

				hdrs = sc_module.session.headers.copy()
				request.headers.update(hdrs)

				if len(sc_module.cookie) > 0: request.headers['cookie'] = sc_module.cookie

				response, err = self._fetch(url, request.verb, request.postdata, request.headers)

				msgs = []
				if response:
					if request.source == AUTH_RESPONSE_KEY:
						msgs.append('Authentication %s: [%s] status: %s' % (request.verb, request.url_string, str(response.status)))
					else:
						msgs.append('%s: [%s] status: %s' % (request.verb, request.url_string, str(response.status)))
					if sc_module.session.log.get('request_headers'): msgs.append('\tREQUEST HEADERS: %s' % request.headers)
					if sc_module.session.log.get('post_data') and len(request.postdata) > 0: msgs.append('\tPOST DATA: %s' % request.postdata)
					if sc_module.session.log.get('response_headers'): msgs.append('\tRESPONSE HEADERS: %s' % response.headers)
				else:
					if err:
						msgs.append('ERROR: %s' % err)
					if not sc_module.RequestQueue.retry(request):
						msgs.append('\tERROR: Exceeded max_retries for: [%s]' % request.url_string)
					continue

				# TODO: Proper cookie support
				if response.headers.has_key('set-cookie'):
					if len(sc_module.cookie) == 0: sc_module.cookie = response.headers['set-cookie']

				if (response.status >= 300 and response.status < 400) and request.url.netloc == sc_module.session.domain:
					if 'location' in response.headers:
						locs = response.headers['location'].strip().split(' ')
						request.redirect(locs[-1])
						if len(locs) > 1:
							msgs.append('\tERROR: Multiple redirect locations found: [%s]' % response.headers['location'])
							msgs.append('\t\tURL: [%s]' % request.url_string)
						if request.redirects > sc_module.session.max_redirects:
							msgs.append('\tERROR: Exceeded %d redirects for: [%s]' % (sc_module.session.max_redirects, request.referrer))
						else:
							sc_module.RequestQueue.put(request)
					else:
						msgs.append('\tERROR: Redirect with no location: [%s]' % request.referrer)

				if response.time > sc_module.session.slow_request:
					msgs.append('\tSLOW REQUEST: [%s] (%.3f seconds)' % (request.url_string, response.time))

				msgs[-1] += '\n'
				sc_module.OutputQueue.put(None, msgs)

				if len(request.modules) == 0: request.modules = sc_module.session.modules
				for name, args in request.modules.iteritems():
					mod = 'modules.%s' % name
					if name == 'spider' and request.source in [AUTH_REQUEST_KEY, AUTH_RESPONSE_KEY]:
						pass
					elif mod in sys.modules:
						try:
							sys.modules[mod].process(request, response)
						except:
							ex = sys.exc_info()
							sc_module.OutputQueue.put(mod, 'ERROR: Processing with module [%s]\n%s' % (name, str(ex[1])))

				if request.source == AUTH_REQUEST_KEY:
					if sc_module.session.auth_post:
						url = sc_module.session.auth_url
					else:
						if len(urlparse.urlparse(sc_module.session.auth_url).query) > 0:
							sep = '&'
						else:
							sep = '?'
						url = '%s%s%s' % (sc_module.session.auth_url, sep, urllib.urlencode(sc_module.session.auth_params, True))

					req = sc_module.Request(AUTH_RESPONSE_KEY, url, url)
					if sc_module.session.auth_post: req.postdata = sc_module.session.auth_params
					sc_module.RequestQueue.put(req)
				elif request.source == AUTH_RESPONSE_KEY:
					# Begin spidering
					print('Checking...')
					sc_module.RequestQueue.put_url('', sc_module.session.page, sc_module.session.page)

def read_input():
	class ReadInputThread(threading.Thread):
		def __init__(self):
			threading.Thread.__init__(self)
			self.input = None

		def run(self):
			try:
				self.input = raw_input()
			except:
				pass

	it = ReadInputThread()
	it.start()
	it.join(60)
	return it.input
	
def complete(threads):
	cmpl = False
	if sc_module.RequestQueue.empty():
		cmpl = True
		for t in threads:
			if t.active:
				cmpl = False
	return cmpl

if __name__ == '__main__':
	from argparse import ArgumentParser
	import pickle

	print('''Sitecheck Copyright (C) 2009 Andrew Kershaw
This program comes with ABSOLUTELY NO WARRANTY''')

	parser = ArgumentParser()
	parser.add_argument('-d', '--domain', dest='domain', default=None)
	parser.add_argument('-p', '--page', dest='page', default=None)
	parser.add_argument('directory')
	args = parser.parse_args()

	if len(args.directory) == 0:
		print('Output directory required.')
		sys.exit()

	pth = args.directory
	if pth[-1] != os.sep: pth = pth + os.sep
	suspend_file = pth + 'suspend.pkl'

	resume = False
	if os.path.exists(suspend_file):
		print('Resuming session...')
		try:
			fl = open(suspend_file, 'r')
			suspend_data = pickle.load(fl)
			fl.close()
			sc_module.session = suspend_data[0]
			sc_module.RequestQueue.urls = suspend_data[1]
			sc_module.RequestQueue.from_list(suspend_data[2])
			os.remove(suspend_file)
			resume = True
		except:
			print('Unable to load suspend data.')
			sys.exit()
	else:
		#Load existing configuration
		cfp = '%ssc_config.py' % pth
		if os.path.exists(cfp):
			print('Loading config...')
			import imp
			try:
				sc_module.session = imp.load_source('sc_config', cfp).sc_session()
			except:
				print('Invalid config file found in directory.')
				sys.exit()

		if args.domain:
			d = args.domain
			if not re.match('^http', d, re.IGNORECASE): d = '%s://%s' % (sc_module.session.scheme, d)
			parts = urlparse.urlparse(d)
			sc_module.session.domain = parts.netloc
			sc_module.session.path = parts.path
			if len(parts.query) > 0: sc_module.session.path += '?' + parts.query
		elif len(sc_module.session.domain) > 0:
			pass
		else:
			print('Supply either a domain, a config file or a suspended session.')
			sys.exit()

		if args.page: sc_module.session.page = args.page

		sc_module.session.root = pth
		sc_module.session.output = pth + sc_module.session.output

		if len(sc_module.session.path) == 0: sc_module.session.path = os.sep
		if not sc_module.session.path[0] == os.sep: sc_module.session.path = os.sep + sc_module.session.path
		if not sc_module.session.path[-1] == os.sep and len(os.path.splitext(sc_module.session.path)[1]) == 0: sc_module.session.path = sc_module.session.path + os.sep

		if not sc_module.session.page.lower().startswith(sc_module.session.path): sc_module.session.page = sc_module.session.path + sc_module.session.page

		if sc_module.session.auth_url:
			if not sc_module.session.auth_url.lower().startswith(sc_module.session.path): sc_module.session.auth_url = sc_module.session.path + sc_module.session.auth_url

	# Organise file type sets
	sc_module.session.include_ext = sc_module.session.include_ext.difference(sc_module.session.ignore_ext)
	sc_module.session.test_ext = sc_module.session.test_ext.difference(sc_module.session.ignore_ext.union(sc_module.session.include_ext))

	print('''s -> Suspend
q -> Abort
Return key -> Print status''')

	# Initialise modules
	mods = sc_module.session.modules.keys()
	for m in range(len(mods)):
		name = mods[m]
		full_name = 'modules.%s' % name
		try:
			__import__(full_name)
			if resume:
				if hasattr(sys.modules[full_name], 'resume'): sys.modules[full_name].resume()
			else:
				if hasattr(sys.modules[full_name], 'begin'): sys.modules[full_name].begin()
		except:
			ex = sys.exc_info()
			print('ERROR: Failed to load module [%s]' % name)
			print('%s %s' % (str(ex[0]), str(ex[1])))
			sc_module.session.modules.pop(name)

	print('Target: [%s://%s%s]' % (sc_module.session.scheme, sc_module.session.domain, sc_module.session.path))
	print('Output: [%s]' % sc_module.session.output)

	if sc_module.session.auth_url:
		#Authenticate before spidering begins
		print('Authenticating...')
		sc_module.RequestQueue.put_url(AUTH_REQUEST_KEY, sc_module.session.auth_url, sc_module.session.auth_url)
	else:
		print('Checking...')
		sc_module.RequestQueue.put_url('', sc_module.session.page, sc_module.session.page)

	#Create logging thread
	lw_terminate = threading.Event()
	lw = LogWriter(lw_terminate)
	lw.setDaemon(True)
	lw.start()

	#Create worker thread pool
	threads = []
	sc_terminate = threading.Event()
	for i in range(sc_module.session.thread_pool):
		thread = SiteChecker(sc_terminate)
		thread.setDaemon(True)
		thread.start()
		threads.append(thread)

	suspend = False
	while True:
		char = read_input()
		if char == None:
			if complete(threads): break
		elif char.lower() == 'q':
			break
		elif char.lower() == 's':
			suspend = True
			break
		else:
			print('URLs: %d' % len(sc_module.RequestQueue.urls))
			print('Queue: %d' % sc_module.RequestQueue.qsize())
			if complete(threads): break

	if suspend:
		print('Suspending...')
	else:
		print('Finishing...')

	#Wait for worker threads to complete
	sc_terminate.set()
	for thread in threads:
		thread.join()

	if suspend:
		rq = []
		while not sc_module.RequestQueue.empty():
			rq.append(sc_module.RequestQueue.get(block=False))
		fl = open(suspend_file, 'w')
		#Dump config, url's and requests to file
		pickle.dump((sc_module.session, sc_module.RequestQueue.urls, rq), fl)
		fl.close()
	else:
		for name in sc_module.session.modules.iterkeys():
			mod = 'modules.%s' % name
			if hasattr(sys.modules[mod], 'complete'): sys.modules[mod].complete()

	#Wait for log entries to be written
	lw_terminate.set()
	lw.join()

	print('Completed.')
