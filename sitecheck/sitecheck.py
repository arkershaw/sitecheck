#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys, os, threading, time, httplib, urllib, socket, Queue, datetime, urlparse, re
import sc_module

class LogWriter(threading.Thread):
	def __init__(self, terminate):
		threading.Thread.__init__(self)
		self.terminate = terminate

	def run(self):
		sc_module.ensure_dir(sc_module.session.output)
		self.outfiles = {'sitecheck': open(sc_module.session.output + '/sitecheck.log', 'a')}
		for name in sc_module.session.modules.iterkeys():
			self.outfiles[name] = open(sc_module.session.output + '/' + name + '.log', 'a')

		sc_module.OutputQueue.put(None, 'Started: ' + str(datetime.datetime.now()))

		while not self.terminate.isSet():
			try:
				mod, out = sc_module.OutputQueue.get(block=False)
			except Queue.Empty:
				self.terminate.wait(sc_module.session.wait_seconds)
			else:
				self.outfiles[mod].write(out)

		sc_module.OutputQueue.put(None, 'Completed: ' + str(datetime.datetime.now()))

		while True:
			try:
				mod, out = sc_module.OutputQueue.get(block=False)
			except Queue.Empty:
				break
			else:
				self.outfiles[mod].write(out)

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
			c.sock.settimeout(sc_module.session.request_timeout)
			st = time.time()
			c.request(verb, full_path, urllib.urlencode(postdata), headers)
			r = c.getresponse()
			res = sc_module.Response(r, st)
		except socket.gaierror:
			ex = sys.exc_info()
			err = 'DNS error ' + str(ex[0]) + ' ' + str(ex[1]) # Probably
		except socket.timeout:
			ex = sys.exc_info()
			err = 'Timeout ' + str(ex[0]) + ' ' + str(ex[1])
		except httplib.IncompleteRead:
			ex = sys.exc_info()
			err = 'Read error ' + str(ex[0]) + ' ' + str(ex[1])
		except:
			ex = sys.exc_info()
			err = 'Connection ' + str(ex[0]) + ' ' + str(ex[1])
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
					msgs.append('%s: [%s] status: %s' % (request.verb, request.url_string, str(response.status)))
					if sc_module.session.log.get('request_headers'): msgs.append('\tREQUEST HEADERS: %s' % request.headers)
					if sc_module.session.log.get('post_data') and len(request.postdata) > 0: msgs.append('\tPOST DATA: %s' % request.postdata)
					if sc_module.session.log.get('response_headers'): msgs.append('\tRESPONSE HEADERS: %s' % response.headers)
					if response.is_html:
						doc, err = sc_module.parse_html(response.content)
						if doc == None:
							msgs.append('\tERROR: Unable to parse content [%s]: %s' % (request.url_string, err))
				else:
					if err:
						msgs.append('ERROR: %s' % err)
					if not sc_module.RequestQueue.retry(request):
						msgs.append('\tERROR: Exceeded max_retries for: [%s]' % request.url_string)
					continue

				if response.headers.has_key('set-cookie'):
					sc_module.cookie = response.headers['set-cookie']

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
					if 'modules.' + name in sys.modules:
						try:
							sys.modules['modules.' + name].process(request, response)
						except:
							ex = sys.exc_info()
							sc_module.OutputQueue.put(name, 'ERROR: processing result with module [%s] [%s %s]' % (name, str(ex[0]), str(ex[1])))

if __name__ == '__main__':
	from optparse import OptionParser
	import pickle

	parser = OptionParser()
	parser.add_option('-d', '--domain', dest='domain', default=None)
	parser.add_option('-p', '--page', dest='page', default=None)

	(opts, args) = parser.parse_args()

	if len(args) == 0:
		print 'Output directory required.'
		sys.exit()

	pth = args[0]
	if pth[-1] != '/': pth = pth + '/'
	suspend_file = pth + 'suspend.pkl'

	resume = False
	if os.path.exists(suspend_file):
		print 'Resuming session.'
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
			print 'Unable to load suspend data.'
			sys.exit()
	else:
		if os.path.exists(pth + 'sc_config.py'):
			print 'Loading config.'
			import imp
			try:
				sc_module.session = imp.load_source('sc_config', pth + 'sc_config.py').sc_session()
			except:
				print 'Invalid config file found in directory.'
				sys.exit()

		if opts.domain:
			d = opts.domain
			if not re.match('^http', d, re.IGNORECASE): d = 'http://' + d
			parts = urlparse.urlparse(d)
			sc_module.session.domain = parts.netloc
			sc_module.session.path = parts.path
			if len(parts.query) > 0: sc_module.session.path += '?' + parts.query
		elif len(sc_module.session.domain) > 0:
			pass
		else:
			print 'Supply either a domain, a config file or a suspended session.'
			sys.exit()

		sc_module.session.root = pth
		sc_module.session.output = pth + sc_module.session.output

		if len(sc_module.session.path) == 0: sc_module.session.path = '/'
		if not sc_module.session.path[0] == '/': sc_module.session.path = '/' + sc_module.session.path
		if not sc_module.session.path[-1] == '/' and len(os.path.splitext(sc_module.session.path)[1]) == 0: sc_module.session.path = sc_module.session.path + '/'

	# Organise file type sets
	sc_module.session.include_ext = sc_module.session.include_ext.difference(sc_module.session.ignore_ext)
	sc_module.session.test_ext = sc_module.session.test_ext.difference(sc_module.session.ignore_ext.union(sc_module.session.include_ext))

	# Initialise modules
	mods = sc_module.session.modules.keys()
	for m in range(len(mods)):
		name = mods[m]
		try:
			__import__('modules.' + name)
			if resume:
				if hasattr(sys.modules['modules.' + name], 'resume'): sys.modules['modules.' + name].resume()
			else:
				if hasattr(sys.modules['modules.' + name], 'begin'): sys.modules['modules.' + name].begin()
		except:
			ex = sys.exc_info()
			print 'Failed to load module [%s]' % name
			print str(ex[0]) + ' ' + str(ex[1])
			sc_module.session.modules.pop(name)

	print '''s -> Suspend
q -> Abort
Any key -> Print status'''
	print 'Scanning: [http://' + sc_module.session.domain + sc_module.session.path + ']'
	if opts.page:
		sc_module.RequestQueue.put_url('', sc_module.session.path + opts.page, '')
	else:
		sc_module.RequestQueue.put_url('', sc_module.session.path, '')
	print 'Output: [' + sc_module.session.output + ']'

	lw_terminate = threading.Event()
	lw = LogWriter(lw_terminate)
	lw.setDaemon(True)
	lw.start()

	threads = []
	sc_terminate = threading.Event()
	for i in range(sc_module.session.thread_pool):
		thread = SiteChecker(sc_terminate)
		thread.setDaemon(True)
		thread.start()
		threads.append(thread)

	suspend = False
	while True:
		char = raw_input()
		if char == 'q':
			break
		if char == 's':
			suspend = True
			break
		else:
			print "URLs:", len(sc_module.RequestQueue.urls)
			print "Queue:", sc_module.RequestQueue.qsize()
			if sc_module.RequestQueue.empty():
				ext = True
				for t in threads:
					if t.active:
						ext = False
						break
				if ext: break

	if suspend:
		print 'Suspending...'
	else:
		print 'Finishing...'

	sc_terminate.set()
	for thread in threads:
		thread.join()

	if suspend:
		rq = []
		while not sc_module.RequestQueue.empty():
			rq.append(sc_module.RequestQueue.get(block=False))
		fl = open(suspend_file, 'w')
		pickle.dump((sc_module.session, sc_module.RequestQueue.urls, rq), fl)
		fl.close()
	else:
		for name in sc_module.session.modules.iterkeys():
			if hasattr(sys.modules['modules.' + name], 'complete'): sys.modules['modules.' + name].complete()

	lw_terminate.set()
	lw.join()

	print 'Completed.'
