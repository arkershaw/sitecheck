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

import urlparse
from tidylib import tidy_document
import sc_module

#opts = sc_module.get_args(__name__)
opts = {'show-warnings': True} #'input-encoding': 'utf8'

def process(request, response):
	if response.is_html:
		try:
			doc, err = tidy_document(response.content, options=opts)
		except:
			sc_module.OutputQueue.put(__name__, 'Error parsing: [%s]' % request.url_string)
			return
		else:
			errors = err.splitlines()
			if len(errors) > 0:
				msgs =['Invalid: [%s] (%d errors)' % (request.url_string, len(errors))]
				msgs.extend(['\t%s' % e.replace('line', 'Line') for e in errors])
				sc_module.OutputQueue.put(__name__, msgs)
