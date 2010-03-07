# -*- coding: utf-8 -*-
import re
from BeautifulSoup import Comment
import sc_module

def process(request, response):
	if response.is_html:
		document = sc_module.parse(response.content)
		if document:
			comments = document.findAll(text=lambda text:isinstance(text, Comment))
			if len(comments) > 0:
				sc_module.OutputQueue.put(__name__, 'Document: [%s]' % request.url_string)
				for comment in comments:
					try:
						sc_module.OutputQueue.put(__name__, '\tComment:\t' + re.sub('\r?\n', '\n\t\t\t\t', comment.strip(), re.MULTILINE))
					except UnicodeEncodeError:
						print comment
