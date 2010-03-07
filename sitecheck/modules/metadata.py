# -*- coding: utf-8 -*-
import sc_module
import re

def process(request, response):
	if response.is_html:
		document = sc_module.parse(response.content)
		if document:
			missing = []
			empty = []
			multiple = []

			title = document('title')
			if len(title) == 0:
				missing.append('title')
			elif len(title) > 1:
				multiple.append('title')
			elif title[0].string == None:
				empty.append('title')
			elif len(title[0].string) == 0:
				empty.append('title')

			desc = document('meta', attrs={'name': re.compile('description', re.IGNORECASE)})
			if len(desc) == 0:
				missing.append('description')
			elif len(desc) > 1:
				multiple.append('description')
			else:
				if 'content' in dict(desc[0].attrs):
					if len(desc[0]['content']) == 0:
						empty.append('description')
				else:
					empty.append('description')

			kw = document('meta', attrs={'name': re.compile('keywords', re.IGNORECASE)})
			if len(kw) == 0:
				missing.append('keywords')
			elif len(kw) > 1:
				multiple.append('keywords')
			else:
				if 'content' in dict(kw[0].attrs):
					if len(kw[0]['content']) == 0:
						empty.append('keywords')
				else:
					empty.append('keywords')

			if len(missing) > 0:
				sc_module.OutputQueue.put(__name__, 'Missing: ' + str(missing) + ' in [' + request.url_string + ']')

			if len(empty) > 0:
				sc_module.OutputQueue.put(__name__, 'Empty: ' + str(empty) + ' in [' + request.url_string + ']')

			if len(multiple) > 0:
				sc_module.OutputQueue.put(__name__, 'Multiple: ' + str(multiple) + ' in [' + request.url_string + ']')
