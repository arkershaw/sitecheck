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
import sc_module

def process(request, response):
	if response.status >= 400:
		msgs = ['URL: [%s] returned [%d %s]' % (request.url_string, response.status, response.message)]
		if len(request.referrer) > 0:
			msgs.append('\tReferrer: [%s]' % request.referrer)
		sc_module.OutputQueue.put(__name__, msgs)
