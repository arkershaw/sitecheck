# -*- coding: utf-8 -*-
import re, datetime

class sc_session(object):
	def __init__(self):
		self.output = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S') #Output is appended to the first argument to the script
		#Domain and path are populated by the -d parameter
		self.domain = '' #Domain to spider
		self.path = '' #Restrict to path under the domain
		self.thread_pool = 10 #Number of spider threads to spawn. An extra thread is used for output.
		self.headers = {'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2 (.NET CLR 3.5.30729)'} #Emulate Firefox 3.5 running on Windows XP
		#Only headers are downloaded for the following files
		self.test_only = ['gif', 'jpg', 'jpeg', 'png', 'js', 'css', 'htc', 'swf', 'zip', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv']
		#Allows the inclusion of resources (images, styles etc.) in parent folder of path (if specified). Remove from test_only
		self.include = []
		#self.test_only = ['js', 'css', 'htc', 'swf', 'zip', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv']
		#self.include = ['gif', 'jpg', 'jpeg', 'png']
		self.wait_seconds = 2.0 #Pause between requests to consume less local resources
		self.request_timeout = 30.0
		self.max_retries = 3 #On socket error, a request is returned to the queue
		self.max_redirects = 5 #Trap looping redirects
		self.slow_request = 5.0 #Requests taking longer than this are logged
		self.modules = {
			#'persister': {'output': '', 'headers': True, 'content': True},
			'regexmatch': {
				'Email Address': re.compile("[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", re.IGNORECASE),
				'IP Address': re.compile("\b(?:\d{1,3}\.){3}\d{1,3}\b"),
				'Lorem Ipsum': re.compile("lorem ipsum", re.IGNORECASE)
			},
			'validator': None,
			'accessibility': None,
			'metadata': None,
			'statuslog': None,
			'security': None,
			'comments': None,
			'spelling': {'dictionary': 'en_GB'},
			'readability': {'threshold': 45},
			'spider': None
		}
