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

import tidy, urlparse
import sc_module

#opts = sc_module.get_args(__name__)
opts = {'show-warnings': True}

def process(request, response):
	if response.is_html:
		try:
			res = tidy.parseString(response.content, **opts)
		except:
			sc_module.OutputQueue.put(__name__, 'Error parsing: [%s]' % request.url_string)
			return
		else:
			#try:
			if len(res.errors) > 0:
				msgs =['Invalid: [%s] (%d errors)' % (request.url_string, len(res.errors))]
				for err in res.errors:
					msgs.append('\t%s' % str(err).replace('line', 'Line'))
				sc_module.OutputQueue.put(__name__, msgs)
			#except:
				#File "/usr/lib/python2.6/site-packages/tidy/lib.py", line 81, in __init__
				#self.col = int(tokens[3])
				#ValueError: invalid literal for int() with base 10: 'h545'

				#File "/usr/lib/python2.6/site-packages/tidy/lib.py", line 86, in __init__
				#self.message = tokens[1]
				#IndexError: list index out of range
				#return
