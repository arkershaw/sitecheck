# -*- coding: utf-8 -*-

# Copyright 2009-2013 Andrew Kershaw

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
from sitecheck.core import Struct, Request
from sitecheck.modules import *
from sitecheck.reporting import FlatFile, HTML

media_files = set(['gif', 'jpg', 'jpeg', 'png', 'swf', 'ico'])
resource_files = set(['js', 'css', 'htc'])
document_files = set(['zip', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv'])

class Session(object):
	def __init__(self):
		self.check_for_updates = True # Checks online for current version and search engines in inbound links module
		self.output = '' # Override output folder
		# Domain is populated by the -d parameter
		self.domain = '' # Domain (and path) to spider
		# Page is populated by the -p parameter
		self.page = '' # Start with this page
		self.thread_pool = 10 # Number of spider threads to spawn. An extra thread is used for output.
		self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; rv:12.0) Gecko/20120405 Firefox/14.0.1 Sitecheck'} # Emulate Firefox 14 running on Windows 7
		self.ignore_ext = set([]) # These file types are ignored
		self.test_ext = set.union(media_files, resource_files, document_files) # Only headers are downloaded for these file types
		self.include_ext = set([]) # Allows the inclusion of resources (images, styles etc.) in parent folder of path (if specified)
		self.wait_seconds = 1.0 # Pause between requests to consume less resources
		self.request_timeout = 30.0
		self.max_retries = 3 # On socket error, a request is returned to the queue
		self.max_redirects = 5 # Trap looping redirects
		self.slow_request = 5.0 # Requests taking longer than this are logged
		self.log = Struct(request_headers=True, response_headers=True, post_data=False)
		self.ignore_url = []
		self.report = FlatFile() #HTML()
		self.modules = [
			#Authenticate(login=[Request('login.php'), Request('login.php', post_data=[('username', ''), ('password', '')])], logout=[Request('logout.php')]),
			#RequestList(Request('favicon.ico'), Request('robots.txt')),
			#RequiredPages('privacy-policy.html', 'contact-us.html'),
			DuplicateContent(),
			InsecureContent(),
			#DomainCheck(relay=False),
			#Persister(directory='output'),
			#InboundLinks(engines=['Google', 'Bing']),
			RegexMatch(expressions={
				'Email Address': re.compile("[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", re.IGNORECASE),
				'IP Address': re.compile('(?:\d{1,3}\.){3}\d{1,3}'),
				'Lorem Ipsum': re.compile('lorem ipsum', re.IGNORECASE)
			}),
			#Validator(),
			#Accessibility(),
			MetaData(),
			StatusLog(),
			#Security(email='user@example.com', attacks=["1'1\\'1", '"/><xss>'], quick=True, post=True),
			# WARNING: Using quick=False will result in SIGNIFICANTLY more requests as each parameter will be injected individually
			Comments(),
			#Spelling(language='en_GB'),
			Readability(threshold=45),
			Spider()
		]
