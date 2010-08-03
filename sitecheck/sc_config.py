# -*- coding: utf-8 -*-
import re, datetime

media_files = set(['gif', 'jpg', 'jpeg', 'png', 'swf'])
resource_files = set(['js', 'css', 'htc'])
document_files = set(['zip', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv'])

class sc_session(object):
	def __init__(self):
		self.output = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S') # Output is appended to the first argument to the script
		# Scheme, domain and path are populated by the -d parameter
		self.scheme = 'http'
		self.domain = '' # Domain to spider
		self.path = '' # Restrict to path under the domain
		# Page is populated by the -p parameter
		self.page = '' # Start with this page
		self.thread_pool = 10 # Number of spider threads to spawn. An extra thread is used for output.
		self.headers = {'user-agent': 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2 (.NET CLR 3.5.30729)'} # Emulate Firefox 3.5 running on Windows XP
		self.ignore_ext = set([]) # These file types are ignored
		self.test_ext = set.union(media_files, resource_files, document_files) # Only headers are downloaded for these file types
		self.include_ext = set([]) # Allows the inclusion of resources (images, styles etc.) in parent folder of path (if specified)
		self.wait_seconds = 2.0 # Pause between requests to consume less resources
		self.request_timeout = 30.0
		self.max_retries = 3 # On socket error, a request is returned to the queue
		self.max_redirects = 5 # Trap looping redirects
		self.slow_request = 5.0 # Requests taking longer than this are logged
		self.log = {'request_headers': True, 'response_headers': True, 'post_data': True}
		self.auth_url = None
		self.auth_post = False
		self.auth_params = [('username', ''), ('password', '')]
		self.ignore_url = [] # Add logout url here
		self.modules = {
			#'persister': {'output': 'output', 'headers': True, 'content': True},
			#'inboundlinks': {'engines': ['google', 'yahoo', 'bing']},
			'regexmatch': {
				'Email Address': re.compile("[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", re.IGNORECASE),
				'IP Address': re.compile("\b(?:\d{1,3}\.){3}\d{1,3}\b"),
				'Lorem Ipsum': re.compile("lorem ipsum", re.IGNORECASE)
			},
			'validator': None,
			'accessibility': None,
			'metadata': None,
			'statuslog': None,
			'security': {'email': 'test@test.test', 'attacks': ["1'1\\'1", '"/><xss>']},
			# "' -- ", "\\' -- ", "; select 1/0;", "'';!--\"<xss>=&{()}"
			'comments': None,
			'spelling': {'dictionary': 'en_GB'},
			'readability': {'threshold': 45},
			'spider': None
		}
