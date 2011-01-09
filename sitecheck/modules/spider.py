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

import urlparse, re
import sc_module

def process(request, response):
	if response.is_html:
		referrer = request.url_string
		msgs = ['Location: [%s]' % request.url_string]

		sc_module.RequestQueue.put_urls(__name__, map(lambda e: e[2], gather(response.content, 'src')), referrer)
		sc_module.RequestQueue.put_urls(__name__, map(lambda e: e[2], gather(response.content, 'action', 'form')), referrer)

		urls = set()
		for href in gather(response.content, 'href'):
			if href[0] == 'a':
				urls.add(href[2])
			sc_module.RequestQueue.put_url(__name__, href[2], referrer)

		out = list(urls)
		out.sort()
		for url in out:
			if url.count(' ') > 0:
				msgs.append('\t-> [%s] *Unencoded' % url)
			else:
				msgs.append('\t-> [%s]' % url)

		sc_module.OutputQueue.put(__name__, msgs)

def gather(document, attribute, element=None):
	# Test strings:
	# < form name = name action = test 1 method = get>
	# < form name = "name" action = "test 1" method = "get">

	flags = re.IGNORECASE | re.DOTALL | re.MULTILINE
	if element:
		rx = re.compile(r'<\s*(?P<element>%s)\b[^>]*?\b%s\s*=\s*(?P<quoted>")?(?P<attr>.*?)(?(quoted)"|[\s>])' \
			% (element, attribute), flags)
	else:
		rx = re.compile(r'<\s*(?P<element>[\w]+)\b[^>]*?\b%s\s*=\s*(?P<quoted>")?(?P<attr>.*?)(?(quoted)"|[\s>])' \
			% attribute, flags)

	mtchs = rx.finditer(document)
	for m in mtchs:
		url = m.group('attr')
		if not url.startswith('#') and not url.lower().startswith('javascript:'):
			yield (m.group('element'), attribute, url)
