# -*- coding: utf-8 -*-
import urlparse
import sc_module

def process(request, response):
	if response.is_html:
		doc, err = sc_module.parse_html(response.content)
		if doc:
			referrer = request.url_string

			sc_module.RequestQueue.put_urls(__name__, gather(doc, None, 'src'), referrer)
			sc_module.RequestQueue.put_urls(__name__, gather(doc, None, 'href'), referrer)
			#sc_module.RequestQueue.put_urls(__name__, gather(document, 'script', 'src'), referrer)
			sc_module.RequestQueue.put_urls(__name__, gather(doc, 'form', 'action'), referrer)

			urls = set()
			sc_module.OutputQueue.put(__name__, 'Location: [%s]' % request.url_string)
			for a in doc('a', attrs={'href': True}):
				urls.add(a['href'])

			out = list(urls)
			out.sort()
			for url in out:
				if url.count(' ') > 0:
					sc_module.OutputQueue.put(__name__, '\t-> [%s] *Unencoded' % url)
				else:
					sc_module.OutputQueue.put(__name__, '\t-> [%s]' % url)

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
