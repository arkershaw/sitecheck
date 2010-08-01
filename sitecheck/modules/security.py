# -*- coding: utf-8 -*-
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
		doc, err = sc_module.parse_html(response.content)
		if doc:
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

	#Empty query string parameters are not returned by urlparse.parse_qs
	mtchs = eqs.finditer(request.url.query)
	for mtch in mtchs:
		qs = re.sub(mtch.group(0) + '(?:&|$)', mtch.group(0) + value, request.url.query)
		url = urlparse.urljoin(request.url_string, '?' + qs)
		req = sc_module.Request(__name__, url, request.referrer)
		req.modules = {__name__[8:]: None}
		sc_module.RequestQueue.put(req)

	if document:
		postdata = []
		for f in document('form'):
			url = request.url_string
			post = False
			if ('action' in dict(f.attrs)):
				url = f['action']
			if ('method' in dict(f.attrs)):
				if f['method'].upper() == 'POST': post = True

			params = []
			inputs = f({'input': True, 'textarea': True, 'select': True})
			for i in inputs:
				attrs = dict(i.attrs)
				if 'name' in attrs:
					name = attrs['name']

					val = attrs.get('value')
					if not val: val = ''
					if len(val) == 0:
						if name.lower().find('date') > -1:
							val = '1/1/2000'
						elif name.lower().find('email') > -1:
							val = email
						else:
							val = '1'
					params.append((name, val))

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

def insert_param(item, name, value):
	if item[0] == name:
		return (name, value)
	else:
		return item