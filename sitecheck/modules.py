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

import re
import os
import datetime
import urllib.parse
import urllib.request
from io import StringIO
import json

try:
	from tidylib import tidy_document
except:
	_tidy_available = False
else:
	_tidy_available = True

try:
	import enchant
	from enchant.checker import SpellChecker
	from enchant.tokenize import EmailFilter, URLFilter
except:
	_enchant_available = False
else:
	_enchant_available = True

try:
	from domaincheck import DomainInfo
except:
	_domaincheck_available = False
else:
	_domaincheck_available = True

from sitecheck.core import Request, ModuleBase, HtmlHelper, Checker, message_batch
from sitecheck.utils import ensure_dir, html_decode

class Spider(ModuleBase):
	@message_batch
	def process(self, messages, request, response):
		if response.is_html:
			doc = HtmlHelper(response.content)

			referrer = str(request)
			messages.add('Location: [{}]'.format(referrer))

			self.add_request([e[2] for e in doc.get_attribute('src')], referrer)
			self.add_request([e[2] for e in doc.get_attribute('action', 'form')], referrer)

			urls = set()
			for href in doc.get_attribute('href'):
				if href[0] == 'a':
					if self.sitecheck.request_queue.is_valid(href[2]): urls.add(href[2])
				self.add_request(href[2], referrer)

			out = list(urls)
			out.sort()
			for url in out:
				if url.count(' ') > 0:
					messages.add('\t-> [{}] *Unencoded'.format(url))
				else:
					messages.add('\t-> [{}]'.format(url))

class StatusLog(ModuleBase):
	@message_batch
	def process(self, messages, request, response):
		if response.status >= 400:
			messages.add('URL: [{}] returned [{} {}]'.format(str(request), response.status, response.message))
			if len(request.referrer) > 0:
				messages.add('\tReferrer: [{}]'.format(request.referrer))

class Accessibility(ModuleBase):
	def __init__(self):
		super(Accessibility, self).__init__()
		self.accessibility = re.compile(' - Access: \[([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\]')
		self.ignore = set()
		self.ignore.add('1.1.2.1') # <img> missing 'longdesc' and d-link
		self.ignore.add('2.1.1') # ensure information not conveyed through color alone.
		self.ignore.add('6.1.1') # style sheets require testing
		self.ignore.add('6.2.2') # text equivalents require updating
		self.ignore.add('6.3.1') # programmatic objects require testing
		self.ignore.add('7.1.1') # remove flicker
		self.ignore.add('8.1.1') # ensure programmatic objects are accessible

		self.options = {'show-warnings': False, 'accessibility-check': 1}

	def begin(self):
		global _tidy_available
		if not _tidy_available:
			self.add_message('ERROR: tidylib not available')

	@message_batch
	def process(self, messages, request, response):
		global _tidy_available
		if response.is_html and _tidy_available:
			try:
				doc, err = tidy_document(response.content, options=self.options)
			except:
				messages.add('Error parsing: [{}]'.format(str(request)))
			else:
				for e in err.splitlines():
					if self.log(e):
						messages.add('\t{}'.format(re.sub('^line\\b', 'Line', e)))

				messages.set_header('URL: {} ({} errors)'.format(str(request), len(messages)))

	def log(self, error):
		mtch = self.accessibility.search(error)
		log = False
		if mtch:
			log = True
			txt = ''
			for grp in mtch.groups():
				if len(txt) > 0: txt += '.'
				txt += grp
				if txt in self.ignore:
					log = False
					break
		return log

class Comments(ModuleBase):
	@message_batch
	def process(self, messages, request, response):
		if response.is_html:
			doc = HtmlHelper(response.content)
			messages.set_header('URL: [%s]' % str(request))
			for comment in doc.get_comments():
				c = comment.strip()
				if c.startswith('[if') and c.endswith('<![endif]'):
					# Ignore IE conditional comments
					pass
				else:
					messages.add('\tComment:\t{}'.format(re.sub('\r?\n', '\n\t\t\t\t', c, re.MULTILINE)))

class MetaData(ModuleBase):
	@message_batch
	def process(self, messages, request, response):
		if response.is_html:
			doc = HtmlHelper(response.content)
			missing = []
			empty = []
			multiple = []

			title = [t for t in doc.get_element('title')]
			if len(title) == 0:
				missing.append('title')
			elif len(title) > 1:
				multiple.append('title')
			else:
				txt = [t for t in title[0].get_text()]
				if len(txt) == 0:
					empty.append('title')

			meta = {'description': [0, ''], 'keywords': [0, '']}
			for e in doc.get_element('meta'):
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

			messages.set_header('URL: {}'.format(str(request)))

			if len(missing) > 0:
				messages.add('\tMissing: {}'.format(str(missing)))

			if len(empty) > 0:
				messages.add('\tEmpty: {}'.format(str(empty)))

			if len(multiple) > 0:
				messages.add('\tMultiple: {}'.format(str(multiple)))

class Readability(ModuleBase):
	def __init__(self, threshold=45):
		super(Readability, self).__init__()
		self.threshold = threshold
		self.sentence_end = '!?.'
		self.min = None
		self.max = None
		self.count = 0
		self.total = 0

	def complete(self):
		if self.count > 0:
			self.add_message('SUMMARY: Min {:.2f}, Max {:.2f}, Avg {:.2f}'.format(self.min, self.max, self.total / self.count))

	def process(self, request, response):
		if response.is_html:
			doc = HtmlHelper(response.content)
			doc.strip_comments()
			doc.strip_element(('script', 'style'))

			all_text = ''
			for txt in doc.get_text():
				if len(txt.strip()) > 0:
					all_text += txt.strip().lower()
					if all_text[-1] in self.sentence_end:
						all_text += ' '
					else:
						all_text += '. '

			all_text = all_text.strip()
			if len(all_text) > 0:
				twrd = float(self.words(all_text))
				tsnt = float(self.sentences(all_text))
				tsyl = float(self.syllables(all_text))

				fkre = 206.835 - 1.015 * (twrd / tsnt) - 84.6 * (tsyl / twrd)

				with self.sync_lock:
					self.count += 1
					self.total += fkre
					if self.min == None:
						self.min = fkre
					else:
						self.min = min(self.min, fkre)

					if self.max == None:
						self.max = fkre
					else:
						self.max = max(self.max, fkre)

				if fkre < self.threshold:
					self.add_message('Document: [{}] readability: [{:.2f}]'.format(str(request), fkre))

	def words(self, text):
		return len(text.split(' '))

	def sentences(self, text):
		s = 0
		for se in self.sentence_end:
			s += text.count(se)
		if s == 0: s = 1
		return s

	def syllables(self, text):
		s = 0
		for word in text.split(' '):
			w = re.sub('\W', '', word)
			if len(w) <= 3:
				s += 1
			else:
				w = re.sub('(?:es|ed|[^l]e)$', '', w)
				s += len(re.findall('[aeiouy]{1,2}', w))
				s += len(re.findall('eo|ia|ie|io|iu|ua|ui|uo', w))
		if s == 0: s = 1
		return s

class Validator(ModuleBase):
	def __init__(self):
		super(Validator, self).__init__()
		self.options = {'show-warnings': True}

	def begin(self):
		global _tidy_available
		if not _tidy_available:
			self.add_message('ERROR: tidylib not available')

	@message_batch
	def process(self, messages, request, response):
		global _tidy_available
		if response.is_html and _tidy_available:
			try:
				doc, err = tidy_document(response.content, options=self.options)
			except:
				messages.add('ERROR: Unable to parse: [{}]'.format(str(request)))
			else:
				for e in err.splitlines():
					messages.add('\t{}'.format(re.sub('^line\\b', 'Line', e)))

				messages.set_header('Invalid: [{}] ({} errors)'.format(str(request), len(messages)))

class RegexMatch(ModuleBase):
	def __init__(self, expressions={}):
		super(RegexMatch, self).__init__()
		self.expressions = expressions

	@message_batch
	def process(self, messages, request, response):
		messages.set_header('URL: {}'.format(str(request)))
		for rx in self.expressions.items():
			inv_h = inv_b = False
			if rx[0][0] == '^':
				inv_h = True
			elif rx[0][0] == '_':
				inv_b = True

			if inv_h:
				if not rx[1].search(str(response.headers)):
					messages.add('Filter: [{}] not found in headers'.format(rx[0]))
			elif not inv_b:
				mtchs = rx[1].finditer(str(response.headers))
				for mtch in mtchs:
					messages.add('Filter: [{}] found: [{}] in headers'.format(rx[0], mtch.group()))

			if response.is_html:
				if inv_b:
					if not rx[1].search(str(response.content)):
						messages.add('Filter: [{}] not found'.format(rx[0]))
				elif not inv_h:
					mtchs = rx[1].finditer(response.content)
					for mtch in mtchs:
						messages.add('\tFilter: [{}] found: [{}]'.format(rx[0], mtch.group()))

class Persister(ModuleBase):
	def __init__(self, directory='output'):
		super(Persister, self).__init__()
		self.directory = directory

	def process(self, request, response):
		if request.verb == 'HEAD' and response.status < 300 and request.domain == urllib.parse.urlparse(self.sitecheck.session.domain).netloc:
			request.set_verb()
			request.modules = [self]
			self.sitecheck.request_queue.put(request)
		elif len(response.content) > 0 and response.status < 300:
			od = self.sitecheck.root_path + self.sitecheck.session.output + os.sep
			if len(self.directory) >  0: od += self.directory + os.sep
			od += request.domain

			parts = request.path.split('/')
			if len(parts) > 1:
				if parts[-1] == '': parts[-1] = '__index'
				od += os.sep.join(parts[0:-1])
				fl = parts[-1]
			else:
				fl = '__index'

			ensure_dir(od)

			if len(request.query) > 0: fl += '?' +  urllib.parse.unquote_plus(request.query)
			fl = re.sub(r'([ \/])', '', fl)

			pth = os.path.join(od, fl)
			if response.is_html and not re.search('\.html?$', pth, re.IGNORECASE):
				pth += '.html'

			if response.is_html:
				open(pth, mode='w').write(response.content)
			else:
				open(pth, mode='wb').write(response.content)

class Spelling(ModuleBase):
	def __init__(self, language='en_US'):
		super(Spelling, self).__init__()
		self.language = language
		self.sentence_end = '!?.'

	def __getstate__(self):
		state = self._clean_state(dict(self.__dict__))
		del state['spell_checker']
		return state

	def begin(self):
		global _enchant_available
		if _enchant_available:
			ddp = os.path.dirname(os.path.abspath(__file__)) + 'dict.txt'
			cdp = self.sitecheck.root_path + 'dict.txt'

			if os.path.exists(cdp):
				self.add_message('Using custom dictionary [{}]'.format(cdp))
				d = enchant.DictWithPWL(self.language, cdp)
			elif os.path.exists(ddp):
				self.add_message('Using default custom dictionary')
				d = enchant.DictWithPWL(self.language, ddp)
			else:
				self.add_message('No custom dictionary found')
				d = enchant.Dict(self.language)

			self.spell_checker = SpellChecker(d, filters=[EmailFilter, URLFilter])
		else:
			self.add_message('ERROR: pyenchant not available')

	@message_batch
	def process(self, messages, request, response):
		global _enchant_available
		if response.is_html and _enchant_available:
			doc = HtmlHelper(response.content)
			doc.strip_comments()
			doc.strip_element(('script', 'style'))

			words = {}
			with self.sync_lock:
				for txt in doc.get_text():
					self.check(txt, words)
				for txt in doc.get_attribute('title'):
					self.check(txt[2], words)
				for txt in doc.get_attribute('alt'):
					self.check(txt[2], words)
				for e in doc.get_element('meta'):
					names = [n for n in e.get_attribute('name')]
					if len(names) > 0:
						name = names[0][2].lower()
						if name == 'description' or name == 'keywords':
							content = [c for c in e.get_attribute('content')]
							if len(content) > 0:
								self.check(content[0][2], words)

			if len(words) > 0:
				messages.set_header('Document: [{}]'.format(str(request)))
				keys = list(words.keys())
				keys.sort()
				for k in keys:
					messages.add('\tWord: [{}] x {} ({})'.format(words[k][0], words[k][1], words[k][2]))

	def check(self, text, words):
		if not text: return
		t = html_decode(text.strip())
		l = len(t)
		if l > 0:
			self.spell_checker.set_text(t)
			for err in self.spell_checker:
				if err.word[1].islower(): # Ignore abbreviations
					w = err.word.lower()
					if w in words:
						words[w][1] += 1
					else:
						ctx = ''
						m = re.search(r'(.)?\s*\b(%s)\b' % err.word, t)
						if m:
							if m.start() == 0 or m.group(1) in self.sentence_end or m.group(2)[0].islower(): # First word in sentence/para or not proper noun
								st = max(m.start() - 20, 0)
								en = min(m.end() + 20, l)
								ctx = re.sub('\t|\n', ' ', t[st:en])
								words[w] = [err.word, 1, ctx]

class InboundLinks(ModuleBase):
	def __init__(self, engines=None):
		super(InboundLinks, self).__init__()
		self.engines = engines
		#URL, page regex, page size, initial offset
		self.engine_parameters = {
			'Google': [
				'http://www.google.co.uk/search?num=100&q=site:{}&start={}&as_qdr=all',
				re.compile('(?:About )?([0-9,]+) results', re.IGNORECASE),
				100, 0
			],
			'Yahoo': [
				'http://siteexplorer.search.yahoo.com/siteexplorer/search?p={}&b={}',
				re.compile('Pages \(([0-9,\.]+)', re.IGNORECASE),
				100, 1
			],
			'Bing': [
				'http://www.bing.com/search?q=site%%3A{}&first={}',
				re.compile('[0-9,]+-[0-9,]+ of ([0-9,]+) results', re.IGNORECASE),
				10, 1
			]
		}
		self.inbound = set()

	def begin(self):
		if hasattr(self.sitecheck.session, 'check_for_updates') and self.sitecheck.session.check_for_updates:
			try:
				settings = urllib.request.urlopen('http://sitecheck.sourceforge.net/search-engines.js').read().decode('utf-8')
				ss = StringIO(settings)
				sd = json.load(ss)
				for k in sd:
					sd[k][1] = re.compile(sd[k][1], re.IGNORECASE)
			except:
				self.add_message('Update check failed - please notify: arkershaw@users.sourceforge.net')
			else:
				self.engine_parameters = sd

		self.link = re.compile('"(https?://{}[^"]*)"'.format(re.escape(self.sitecheck.session.domain), re.IGNORECASE))
		if not self.engines: self.engines = list(self.engine_parameters.keys())
		for ei in range(len(self.engines)):
			se = self.engines[ei]
			if se in self.engine_parameters:
				e = self.engine_parameters[se]
				e.extend([0, e[3]]) # Total results, current result offset
				url = e[0].format(self.sitecheck.session.domain, e[3])
				req = Request(self.name, url, se)
				req.modules = [self]
				req.verb = 'GET'
				self.sitecheck.request_queue.put(req)
			else:
				self.add_message('ERROR: Unknown search engine [{}]'.format(se))
				self.engines.pop(ei)

	def process(self, request, response):
		if request.source == self.name and response.is_html and request.referrer in self.engine_parameters:
			with self.sync_lock:
				e = self.engine_parameters[request.referrer]
				mtch = e[1].search(response.content)
				if mtch == None:
					self.add_message('ERROR: Unable to calculate pages [{}]'.format(str(request)))
				else:
					e[4] = int(re.sub('[^0-9]', '', mtch.groups()[0]))

					for m in self.link.finditer(response.content):
						url = m.groups()[0]
						self.inbound.add(url)
						self.add_request(url, str(request))

					e[5] += e[2]
					if e[5] < e[4]:
						url = e[0].format((self.sitecheck.session.domain, e[5]))
						req = Request(self.name, url, request.referrer)
						req.modules = [self]
						req.verb = 'GET'
						self.sitecheck.request_queue.put(req)

	def complete(self):
		urls = list(self.inbound)
		urls.sort()
		self.add_message(urls)
		self.add_message('Total: {}'.format(len(self.inbound)))

class Security(ModuleBase):
	def __init__(self, email='', attacks=[]):
		super(Security, self).__init__()
		self.xss = re.compile("<xss>", re.IGNORECASE)
		self.email = email
		self.attacks = attacks

	@message_batch
	def process(self, messages, request, response):
		if request.source == self.name:
			if response.status >= 500:
				messages.add('Caused error with request: [{}]'.format(str(request)))
				if len(request.postdata) > 0:
					messages.add('\tPost data: [{}]'.format(urllib.parse.urlencode(request.postdata)))
			elif self.xss.search(response.content):
				messages.add('Possible XSS found in: [{}]'.format(str(request)))
				if len(request.postdata) > 0:
					messages.add('\tPost data: [{}]'.format(urllib.parse.urlencode(request.postdata)))
		elif response.is_html:
			doc = HtmlHelper(response.content)
			for atk in self.attacks:
				self.inject(request, doc, atk)

	def inject(self, request, document, value):
		qs = urllib.parse.parse_qs(request.query, True)
		for param in qs.keys():
			temp = qs[param]
			qs[param] = value
			url = urllib.parse.urljoin(str(request), '?' + urllib.parse.urlencode(qs, True))
			qs[param] = temp

			req = Request(self.name, url, request.referrer)
			req.modules = [self]
			self.sitecheck.request_queue.put(req)

		postdata = []
		for f in document.get_element('form'):
			url = str(request)
			post = False

			for a in f.get_attribute('action', 'form'):
				if len(a[2]) > 0: url = a[2]
				break

			for m in f.get_attribute('method', 'form'):
				if m[2].upper() == 'POST': post = True
				break

			params = []
			self.get_fields(f, 'input', params)
			self.get_fields(f, 'textarea', params)
			self.get_fields(f, 'select', params)

			for cp in params:
				rp = [self.insert_param(p, cp[0], value) for p in params] # Construct new list
				if not post:
					if len(urllib.parse.urlparse(url).query) > 0:
						url = url + '&' + urllib.parse.urlencode(rp)
					else:
						url = url + '?' + urllib.parse.urlencode(rp)

				req = Request(self.name, url, request.referrer)
				if post: req.postdata = rp
				req.modules = [self]
				self.sitecheck.request_queue.put(req)

	def get_fields(self, form, element, params):
		for e in form.get_element(element):
			name = ''
			for n in e.get_attribute('name', element):
				name = n[2]
				break

			if len(name) > 0:
				val = ''
				for v in e.get_attribute('value', element):
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

	def insert_param(self, item, name, value):
		if item[0] == name:
			return (name, value)
		else:
			return item

class DomainCheck(ModuleBase):
	def __init__(self, relay=False):
		self.relay = relay

	def begin(self):
		global _domaincheck_available
		if _domaincheck_available:
			today = datetime.date.today()

			print('Testing: {}'.format(args.domain))

			d = DomainInfo(args.domain)

			if type(d.domain_expiry) == datetime.date:
				rem = (d.domain_expiry - today).days
				if rem < 0:
					print('Domain expired {}'.format(d.domain_expiry))
				else:
					print('Domain expires in {} days'.format(rem))
			elif d.domain_expiry:
				print('Domain expires on: {}'.format(d.domain_expiry))
			else:
				print('Unable to determine domain expiry date')

			if d.spf:
				print('SPF: {}'.format(d.spf))
			else:
				print('No SPF record found')

			print('Hosts:')
			for host in d.hosts:
				h = d.hosts[host]
				print('\t{} ({})'.format(h.address, h.name))

				if h.cert_expiry:
					rem = (h.cert_expiry - today).days
					if rem < 0:
						print('\t\tCertificate expired {}'.format(h.cert_expiry))
					else:
						print('\t\tCertificate expires in {} days'.format(rem))

				if h.sslv2:
					print('\t\tInsecure ciphers supported')

				if args.relay:
					relay, failed = test_relay(h.address)
					if relay:
						for f in failed:
							print('\t\tPossible open relay: {} -> {}'.format(f[0], f[1]))
