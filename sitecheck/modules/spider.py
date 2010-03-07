# -*- coding: utf-8 -*-
import urlparse
import sc_module

def process(request, response):
	if response.is_html:
		document = sc_module.parse(response.content)
		if document:
			urls = set()
			referrer = request.url_string
			sc_module.OutputQueue.put(__name__, 'Location: [%s]' % request.url_string)
			elements = document('a', attrs={'href': True})
			for e in elements:
				sc_module.RequestQueue.put_url(__name__, e['href'], referrer)
				urls.add(e['href'])

			out = list(urls)
			out.sort()
			for url in out:
				if url.count(' ') > 0:
					sc_module.OutputQueue.put(__name__, '\t-> [%s] *Unencoded' % url)
				else:
					sc_module.OutputQueue.put(__name__, '\t-> [%s]' % url)

			sc_module.RequestQueue.put_urls(__name__, gather(document, 'img', 'src'), referrer)
			sc_module.RequestQueue.put_urls(__name__, gather(document, 'link', 'href'), referrer)
			sc_module.RequestQueue.put_urls(__name__, gather(document, 'script', 'src'), referrer)

def gather(document, element, attribute):
	elements = document(element, attrs={attribute: True})
	for e in elements:
		yield e[attribute]
