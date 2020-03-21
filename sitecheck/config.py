# -*- coding: utf-8 -*-

# Copyright 2009-2020 Andrew Kershaw

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
from sitecheck.reporting import *

media_files = {'gif', 'jpg', 'jpeg', 'png', 'swf', 'ico'}
resource_files = {'js', 'css', 'htc'}
document_files = {'zip', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv'}


class Session(object):
	def __init__(self):
		# Checks online for current version and search engines in inbound links module.
		self.check_for_updates = True
		# Override output folder.
		self.output = ''
		# Domain (and path) to spider. Domain can also be populated by the -d parameter.
		self.domain = ''
		# Start with this page. Page can also be populated by the -p parameter.
		self.page = ''
		# Number of spider threads to spawn. An extra thread is used for output.
		self.thread_pool = 10
		# Emulate Firefox 73 running on Windows 10.
		self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:73.0) Gecko/20100101 Firefox/73.0 Sitecheck'}
		# These file types are ignored.
		self.ignore_ext = set([])
		# Only headers are downloaded for these file types.
		self.test_ext = set.union(media_files, resource_files, document_files)
		# Allows the inclusion of resources (images, styles etc.) in parent folder of path (if specified).
		self.include_ext = set([])
		# Pause between requests to consume less resources.
		self.wait_seconds = 1.0
		# Time to wait for a response from server.
		self.request_timeout = 30.0
		# On socket error, a request is returned to the queue.
		self.max_retries = 3
		# Trap looping redirects.
		self.max_redirects = 5
		# Maximum number of requests in a scan (0 is no limit).
		self.max_requests = 0
		# Requests taking longer than this are logged.
		self.slow_request = 5.0
		self.log = Struct(request_headers=True, response_headers=True, post_data=False)
		self.ignore_url = []
		self.report = FlatFile(directory='txt')  # HTML(directory='html')
		self.modules = [
			# Authenticate(
			# 	login=[
			# 		Request('login.php'),
			# 		Request('login.php', post_data=[('username', ''), ('password', '')])
			# 	],
			# 	logout=[
			# 		Request('logout.php')
			# 	]
			# ),
			RequestList(Request('favicon.ico'), Request('robots.txt')),
			# RequiredPages('privacy-policy.html', 'contact-us.html'),
			DuplicateContent(content=True, content_length=25),
			InsecureContent(),
			# Scan domain is checked automatically
			# DomainCheck(relay=False, domains=['alternate-domain-1.com', 'alternate-domain-2.com']),
			# Persister(directory='output'),
			# InboundLinks(engines=['Google', 'Bing']),
			RegexMatch(expressions={
				'Email Address': re.compile("[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", re.IGNORECASE),
				'IP Address': re.compile('(?:\d{1,3}\.){3}\d{1,3}'),
				'Lorem Ipsum': re.compile('lorem ipsum', re.IGNORECASE)
			}),
			# Validator(),
			# Accessibility(),
			MetaData(),
			StatusLog(),
			# Security(email='user@example.com', attacks=["1'1\\'1", '"/><xss>'], quick=True, post=True),
			# WARNING: Using quick=False will result in SIGNIFICANTLY more requests as each parameter will be injected individually
			Comments(),
			# Spelling(language='en_GB'),
			Readability(threshold=45),
			Spider()
		]
