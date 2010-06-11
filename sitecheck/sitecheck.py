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
			__import__('modules.' + name)
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

	def fetch(self, url, verb='GET', postdata={}, headers={}):
		full_path = url.path
		if len(url.query) > 0: full_path += '?' + url.query
		full_url = url.scheme + '://' + url.netloc + full_path
		if url.scheme == 'https':
			c = httplib.HTTPSConnection(url.netloc)
		else:
			c = httplib.HTTPConnection(url.netloc)
		hdrs = sc_module.session.headers.copy()
		hdrs.update(headers)
		res = None
		try:
			c.connect()
			c.sock.settimeout(sc_module.session.request_timeout)
			st = time.time()
			c.request(verb, full_path, urllib.urlencode(postdata), hdrs)
			r = c.getresponse()
			res = sc_module.Response(r, st)
		except socket.gaierror:
			self.error(full_url, 'DNS error') #Probably
		except socket.timeout:
			self.error(full_url, 'Timeout')
		except httplib.IncompleteRead:
			self.error(full_url, 'Read error')
		except:
			self.error(full_url, 'Connection')
		finally:
			c.close()

		if res:
			sc_module.OutputQueue.put(None, verb + ': [' + full_url + '] status: ' + str(res.status))
			doc = sc_module.parse(res.content)
			if doc == None:
				sc_module.OutputQueue.put(None, 'ERROR: Unable to parse content [%s]' % full_url)
		return res

	def error(self, url, message):
		sc_module.OutputQueue.put(None, message + ': [' + url + ']')
		sc_module.OutputQueue.put(None, str(sys.exc_info()[0]) + ' ' + str(sys.exc_info()[1]))

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
					ext = os.path.splitext(url.path)[1][1:].lower()
					if not url.netloc == sc_module.session.domain:
						request.verb = 'HEAD'
					elif not url.path.startswith(sc_module.session.path) and not ext in sc_module.session.include:
						request.verb = 'HEAD'
					elif ext in sc_module.session.test_only:
						request.verb = 'HEAD'
					elif len(request.postdata) > 0:
						request.verb = 'POST'
					else:
						request.verb = 'GET'

				#print request.verb, url.path, sc_module.session.path, url.path.startswith(sc_module.session.path)

				response = self.fetch(url, request.verb, request.postdata, request.headers)
				if response == None:
					sc_module.RequestQueue.retry(request)
					continue

				if (response.status >= 300 and response.status < 400) and request.url.netloc == sc_module.session.domain:
					if 'location' in response.headers:
						locs = response.headers['location'].strip().split(' ')
						request.redirect(locs[-1])
						if len(locs) > 1:
							sc_module.OutputQueue.put(None, 'Multiple redirect locations found: [%s]' % response.headers['location'])
							sc_module.OutputQueue.put(None, '\tReferrer: [%s]' % request.referrer)
						if request.redirects > sc_module.session.max_redirects:
							sc_module.OutputQueue.put(None, 'Exceeded %d redirects for: [%s]' % (sc_module.session.max_redirects, request.referrer))
						else:
							sc_module.RequestQueue.put(request)
					else:
						sc_module.OutputQueue.put(None, 'Redirect with no location: [%s]' % request.referrer)

				if response.time > sc_module.session.slow_request:
					sc_module.OutputQueue.put(None, 'Slow request: [%s] (%0.3f seconds)' % (request.url_string, response.time))

				for name, args in request.modules.iteritems():
					if 'modules.' + name in sys.modules:
						sys.modules['modules.' + name].process(request, response)

if __name__ == '__main__':
	from optparse import OptionParser
	import pickle

	parser = OptionParser()
	parser.add_option('-d', '--domain', dest='domain', default=None)

	(opts, args) = parser.parse_args()

	if len(args) == 0:
		print 'Output directory required.'
		sys.exit()

	pth = args[0]
	if pth[-1] != '/': pth = pth + '/'
	suspend_file = pth + 'suspend.pkl'

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
		except:
			print 'Unable to load suspend data.'
	else:
		if os.path.exists(pth + 'sc_config.py'):
			print 'Loading config'
			import imp
			try:
				sc_module.session = imp.load_source('sc_config', pth + 'sc_config.py').sc_session()
			except:
				print 'Invalid config file found in directory.'

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

		sc_module.session.output = pth + sc_module.session.output

		if len(sc_module.session.path) == 0: sc_module.session.path = '/'
		if not sc_module.session.path[0] == '/': sc_module.session.path = '/' + sc_module.session.path
		if not sc_module.session.path[-1] == '/' and len(os.path.splitext(sc_module.session.path)[1]) == 0: sc_module.session.path = sc_module.session.path + '/'

	threads = []
	terminate = threading.Event()
	print '''s -> Suspend
q -> Abort
Any key -> Print status'''
	print 'Scanning: [http://' + sc_module.session.domain + sc_module.session.path + ']'
	sc_module.RequestQueue.put_url('', sc_module.session.path, '')
	print 'Output: [' + sc_module.session.output + ']'

	lw = LogWriter(terminate)
	lw.setDaemon(True)
	lw.start()

	for i in range(sc_module.session.thread_pool):
		thread = SiteChecker(terminate)
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

	terminate.set()
	for thread in threads:
		thread.join()

	lw.join()

	if suspend:
		rq = []
		while not sc_module.RequestQueue.empty():
			rq.append(sc_module.RequestQueue.get(block=False))
		fl = open(suspend_file, 'w')
		pickle.dump((sc_module.session, sc_module.RequestQueue.urls, rq), fl)
		fl.close()

	print 'Completed'
