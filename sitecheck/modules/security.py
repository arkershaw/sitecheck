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

import urlparse, urllib, re
import sc_module

xss = re.compile("<xss>", re.IGNORECASE)
eqs = re.compile("(\w+=)(?:&|$)")
email = sc_module.get_arg(__name__, 'email', 'test@test.test')
attacks = sc_module.get_arg(__name__, 'attacks', [])

def process(request, response):
	if request.source == __name__:
		msgs = []
		if response.status >= 500:
			msgs.append('Caused error with request: [%s]' % request.url_string)
			if len(request.postdata) > 0:
				msgs.append('\tPost data: [%s]' % urllib.urlencode(request.postdata))
		elif xss.search(response.content):
			msgs.append('Possible XSS found in: [%s]' % request.url_string)
			if len(request.postdata) > 0:
				msgs.append('\tPost data: [%s]' % urllib.urlencode(request.postdata))

		if len(msgs) > 0: sc_module.OutputQueue.put(__name__, msgs)

	elif response.is_html:
		doc = sc_module.HtmlHelper(response.content)
		for atk in attacks:
			inject(request, doc, atk)

def inject(request, document, value):
	qs = urlparse.parse_qs(request.url.query)
	for param in qs.iterkeys():
		temp = qs[param]
		qs[param] = value
		url = urlparse.urljoin(request.url_string, '?' + urllib.urlencode(qs, True))
		qs[param] = temp

		req = sc_module.Request(__name__, url, request.referrer)
		req.modules = {__name__[8:]: None}
		sc_module.RequestQueue.put(req)

	# Empty query string parameters are not returned by urlparse.parse_qs
	mtchs = eqs.finditer(request.url.query)
	for mtch in mtchs:
		qs = re.sub(mtch.group(0) + '(?:&|$)', mtch.group(0) + value, request.url.query)
		url = urlparse.urljoin(request.url_string, '?' + qs)
		req = sc_module.Request(__name__, url, request.referrer)
		req.modules = {__name__[8:]: None}
		sc_module.RequestQueue.put(req)

	postdata = []
	for f in document.get_element('form'):
		url = request.url_string
		post = False

		for a in f.get_attribute('action', 'form'):
			if len(a[2]) > 0: url = a[2]
			break

		for m in f.get_attribute('method', 'form'):
			if m[2].upper() == 'POST': post = True
			break

		params = []
		get_fields(f, 'input', params)
		get_fields(f, 'textarea', params)
		get_fields(f, 'select', params)

		# Try an empty request
		req = sc_module.Request(__name__, url, request.referrer)
		req.modules = {__name__[8:]: None}
		sc_module.RequestQueue.put(req)

		for cp in params:
			rp = [insert_param(p, cp[0], value) for p in params] # Construct new list
			if not post:
				if len(urlparse.urlparse(url).query) > 0:
					url = url + '&' + urllib.urlencode(rp)
				else:
					url = url + '?' + urllib.urlencode(rp)

			req = sc_module.Request(__name__, url, request.referrer)
			if post: req.postdata = rp
			req.modules = {__name__[8:]: None}
			sc_module.RequestQueue.put(req)

def get_fields(form, element, params):
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
					val = email
				else:
					val = '1'

			params.append((name, val))

def insert_param(item, name, value):
	if item[0] == name:
		return (name, value)
	else:
		return item
