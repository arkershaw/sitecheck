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

import re, urlparse
import sc_module

args = sc_module.get_args(__name__)

def process(request, response):
	msgs = []
	for rx in args.iteritems():
		inv_h = inv_b = False
		if rx[0][0] == '^':
			inv_h = True
		elif rx[0][0] == '_':
			inv_b = True

		if inv_h:
			if not rx[1].search(str(response.headers)):
				msgs.append('Filter: [%s] not found in headers' % rx[0])
		elif not inv_b:
			mtchs = rx[1].finditer(str(response.headers))
			for mtch in mtchs:
				msgs.append('Filter: [%s] found: [%s] in headers' % (rx[0], mtch.group()))

		if response.is_html:
			if inv_b:
				if not rx[1].search(str(response.content)):
					msgs.append('Filter: [%s] not found' % rx[0])
			elif not inv_h:
				mtchs = rx[1].finditer(response.content)
				for mtch in mtchs:
					msgs.append('\tFilter: [%s] found: [%s]' % (rx[0], mtch.group()))

	if len(msgs) > 0:
		msgs.insert(0, 'URL: %s' % request.url_string)
		sc_module.OutputQueue.put(__name__, msgs)
