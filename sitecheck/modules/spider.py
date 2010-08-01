# -*- coding: utf-8 -*-
import urlparse
import sc_module

def process(request, response):
	if response.is_html:
		doc, err = sc_module.parse_html(response.content)
		if doc:
			referrer = request.url_string

			sc_module.RequestQueue.put_urls(__name__, filter(valid, gather(doc, None, 'src')), referrer)
			sc_module.RequestQueue.put_urls(__name__, filter(valid, gather(doc, None, 'href')), referrer)
			sc_module.RequestQueue.put_urls(__name__, filter(valid, gather(doc, 'form', 'action')), referrer)

			urls = set()
			msgs = ['Location: [%s]' % request.url_string]
			for a in doc('a', attrs={'href': True}):
				urls.add(a['href'])

			out = filter(valid, list(urls))
			out.sort()
			for url in out:
				if url.count(' ') > 0:
					msgs.append('\t-> [%s] *Unencoded' % url)
				else:
					msgs.append('\t-> [%s]' % url)

			sc_module.OutputQueue.put(__name__, msgs)

def valid(url):
	if url.startswith('#'):
		return False
	elif url.lower().startswith('javascript:'):
		return False
	else:
		return True

def gather(document, element, attribute):
	if element and attribute:
		elements = document(element, attrs={attribute: True})
	elif element:
		elements = document(element)
	elif attribute:
		elements = document(attrs={attribute: True})
	else:
		return

	for e in elements:
		yield e[attribute]
