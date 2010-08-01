# -*- coding: utf-8 -*-
from BeautifulSoup import Comment
import re
import sc_module

def process(request, response):
	if response.is_html:
		doc, err = sc_module.parse_html(response.content)
		if doc:
			first = True
			for comment in doc.findAll(text=lambda text:isinstance(text, Comment)):
				c = comment.strip()
				if c.startswith('[if') and c.endswith('<![endif]'):
					# Ignore IE conditional comments
					pass
				else:
					if first:
						first = False
						sc_module.OutputQueue.put(__name__, 'Document: [%s]' % request.url_string)

					try:
						sc_module.OutputQueue.put(__name__, '\tComment:\t' + re.sub('\r?\n', '\n\t\t\t\t', comment.strip(), re.MULTILINE))
					except UnicodeEncodeError:
						print comment
