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

import tidy, urlparse, re
import sc_module

acc = re.compile(' - Access: \[([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\]')
ignore = set()
ignore.add('1.1.2.1') # <img> missing 'longdesc' and d-link
ignore.add('2.1.1') # ensure information not conveyed through color alone.
ignore.add('6.1.1') # style sheets require testing
ignore.add('6.2.2.2') # text equivalents require updating
ignore.add('6.3.1.1') # programmatic objects require testing (script)
ignore.add('7.1.1') # remove flicker
ignore.add('8.1.1.1') # ensure programmatic objects are accessible (script)

opts = {'show-warnings': False, 'accessibility-check': 1}

def process(request, response):
	if response.is_html:
		try:
			res = tidy.parseString(response.content, **opts)
		except:
			sc_module.OutputQueue.put(__name__, 'Error parsing: [%s]' % request.url_string)
			return

		if len(res.errors) > 0:
			errors = list()
			for err in res.errors:
				mtch = acc.search(str(err))
				ign = False
				if mtch:
					txt = ''
					for grp in mtch.groups():
						if len(txt) > 0: txt += '.'
						txt += grp
						if txt in ignore:
							ign = True
							break
					if not ign: errors.append(err)

			if len(errors) > 0:
				msgs = ['URL: %s (%d errors)' % (request.url_string, len(errors))]
				msgs.extend(['\t%s' % e for e in errors])
				sc_module.OutputQueue.put(__name__, msgs)
