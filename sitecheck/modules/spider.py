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
		doc = sc_module.HtmlHelper(response.content)

		referrer = request.url_string
		msgs = ['Location: [%s]' % request.url_string]

		sc_module.RequestQueue.put_urls(__name__, map(lambda e: e[2], doc.get_attribute('src')), referrer)
		sc_module.RequestQueue.put_urls(__name__, map(lambda e: e[2], doc.get_attribute('action', 'form')), referrer)

		urls = set()
		for href in doc.get_attribute('href'):
			if href[0] == 'a':
				if sc_module.RequestQueue.is_valid(href[2]): urls.add(href[2])
			sc_module.RequestQueue.put_url(__name__, href[2], referrer)

		out = list(urls)
		out.sort()
		for url in out:
			if url.count(' ') > 0:
				msgs.append('\t-> [%s] *Unencoded' % url)
			else:
				msgs.append('\t-> [%s]' % url)

		sc_module.OutputQueue.put(__name__, msgs)
