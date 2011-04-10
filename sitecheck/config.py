# -*- coding: utf-8 -*-

# Copyright 2009-2011 Andrew Kershaw

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

import re
from sitecheck.utils import Struct
from sitecheck.modules import *

media_files = set(['gif', 'jpg', 'jpeg', 'png', 'swf'])
resource_files = set(['js', 'css', 'htc'])
document_files = set(['zip', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv'])

class Session(object):
	def __init__(self):
		self.output = '' # Override output folder
		# Domain is populated by the -d parameter
		self.domain = '' # Domain to spider
		# Page is populated by the -p parameter
		self.page = '' # Start with this page
		self.thread_pool = 10 # Number of spider threads to spawn. An extra thread is used for output.
		self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; rv:2.0) Gecko/20110319 Firefox/4.0'} # Emulate Firefox 4 running on Windows 7
		self.ignore_ext = set([]) # These file types are ignored
		self.test_ext = set.union(media_files, resource_files, document_files) # Only headers are downloaded for these file types
		self.include_ext = set([]) # Allows the inclusion of resources (images, styles etc.) in parent folder of path (if specified)
		self.wait_seconds = 2.0 # Pause between requests to consume less resources
		self.request_timeout = 30.0
		self.max_retries = 3 # On socket error, a request is returned to the queue
		self.max_redirects = 5 # Trap looping redirects
		self.slow_request = 5.0 # Requests taking longer than this are logged
		self.log = Struct(request_headers=True, response_headers=True, post_data=False)
		self.authenticate = Struct(login_url=None, logout_url=None, params=[('username', ''), ('password', '')], post=True)
		self.ignore_url = []
		self.ignore_protocol = ['mailto:', 'javascript:']
		self.modules = [
			#Persister(directory='output'),
			#InboundLinks(engines=['Google', 'Yahoo', 'Bing']),
			RegexMatch(expressions={
				'Email Address': re.compile("[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", re.IGNORECASE),
				'IP Address': re.compile('\b(?:\d{1,3}\.){3}\d{1,3}\b'),
				'Lorem Ipsum': re.compile('lorem ipsum', re.IGNORECASE)
			}),
			Validator(),
			Accessibility(),
			MetaData(),
			StatusLog(),
			#Security(email='user@example.com', attacks=["1'1\\'1", '"/><xss>']),
			# "' -- ", "\\' -- ", "; select 1/0;", "'';!--\"<xss>=&{()}"
			Comments(),
			Spelling(language='en_GB'),
			Readability(threshold=45),
			Spider()
		]
