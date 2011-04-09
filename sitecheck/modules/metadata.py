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

import sc_module
import re

def process(request, response):
	if response.is_html:
		doc = sc_module.HtmlHelper(response.content)
		missing = []
		empty = []
		multiple = []

		title = [t for t in doc.get_text(element='title')]
		if len(title) == 0:
			missing.append('title')
		elif len(title) > 1:
			multiple.append('title')
		elif title[0] == None:
			empty.append('title')
		elif len(title[0]) == 0:
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

		msgs = []
		if len(missing) > 0:
			msgs.append('\tMissing: %s' % str(missing))

		if len(empty) > 0:
			msgs.append('\tEmpty: %s' % str(empty))

		if len(multiple) > 0:
			msgs.append('\tMultiple: %s' % str(multiple))

		if len(msgs) > 0:
			msgs.insert(0, 'URL: %s' % request.url_string)
			sc_module.OutputQueue.put(__name__, msgs)
