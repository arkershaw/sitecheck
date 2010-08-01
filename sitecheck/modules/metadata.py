# -*- coding: utf-8 -*-
import sc_module
import re

def process(request, response):
	if response.is_html:
		doc, err = sc_module.parse_html(response.content)
		if doc:
			missing = []
			empty = []
			multiple = []

			title = doc('title')
			if len(title) == 0:
				missing.append('title')
			elif len(title) > 1:
				multiple.append('title')
			elif title[0].string == None:
				empty.append('title')
			elif len(title[0].string) == 0:
				empty.append('title')

			desc = doc('meta', attrs={'name': re.compile('description', re.IGNORECASE)})
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

			kw = doc('meta', attrs={'name': re.compile('keywords', re.IGNORECASE)})
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

			msgs = []
			if len(missing) > 0:
				msgs.append('\tMissing: %s' % str(missing))

			if len(empty) > 0:
				msgs.append('\tEmpty: %s' % str(empty))

			if len(multiple) > 0:
				msgs.append('\tMultiple: %s' % str(multiple))

			if len(msgs) > 0:
				msgs.insert(0, 'URL: %s' % request.url_string)
				sc_module.OutputQueue.put(__name__, msgs)