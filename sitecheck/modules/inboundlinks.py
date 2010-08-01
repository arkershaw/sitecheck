# -*- coding: utf-8 -*-
import urlparse, re
import sc_module

#URL, page regex, link regex, page size, initial offset
engines = {
	'Google': [
		'http://www.google.co.uk/search?q=site:%s&num=100&start=%d&filter=0',
		re.compile('<div id=resultstats>(?:page \d+ of )?(?:about )?([0-9,\.]+)', re.IGNORECASE),
		re.compile('"(https?://' + re.escape(sc_module.session.domain) + '[^"]*)"', re.IGNORECASE),
		100, 0
	],
	'Yahoo': [
		'http://siteexplorer.search.yahoo.com/uk/search?p=%s&b=%d',
		re.compile('<span class="btn">pages \(([0-9,\.]+)', re.IGNORECASE),
		re.compile('"(https?://' + re.escape(sc_module.session.domain) + '[^"]*)"', re.IGNORECASE),
		100, 1
	],
	'Bing': [
		'http://www.bing.com/search?q=site%%3a%s&first=%d',
		re.compile('<span class="sb_count" id="count">[0-9,\.]+-[0-9,\.]+ of ([0-9,\.]+)', re.IGNORECASE),
		re.compile('"(https?://' + re.escape(sc_module.session.domain) + '[^"]*)"', re.IGNORECASE),
		10, 1
	]
}

inbound = set()

def init():
	for se in engines.iterkeys():
		e = engines[se]
		e.extend([0, e[4]]) # Total results, current result offset
		url = e[0] % (sc_module.session.domain, 0)
		req = sc_module.Request(__name__, url, se)
		req.modules = {__name__[8:]: None}
		req.verb = 'GET'
		sc_module.RequestQueue.put(req)

def process(request, response):
	if request.source == __name__ and response.is_html and engines.has_key(request.referrer):
		e = engines[request.referrer]
		mtch = e[1].search(response.content)
		if mtch == None:
			sc_module.OutputQueue.put(__name__, 'ERROR: Unable to calculate pages [%s]' % request.url_string)
			return
		else:
			e[5] = int(re.sub('[^0-9]', '', mtch.groups()[0]))

		for m in e[2].finditer(response.content):
			url = m.groups()[0]
			inbound.add(url)
			sc_module.RequestQueue.put_url(__name__, url, request.url_string)

		e[6] += e[3]
		if e[6] < e[5]:
			url = e[0] % (sc_module.session.domain, e[6])
			req = sc_module.Request(__name__, url, request.referrer)
			req.modules = {__name__[8:]: None}
			req.verb = 'GET'
			sc_module.RequestQueue.put(req)

def complete():
	urls = list(inbound)
	urls.sort()
	for url in urls:
		sc_module.OutputQueue.put(__name__, '%s' % url)
	sc_module.OutputQueue.put(__name__, 'Total: %d' % len(inbound))
