# -*- coding: utf-8 -*-
import tidy, urlparse
import sc_module

#opts = sc_module.get_args(__name__)
opts = {'show-warnings': True}

def process(request, response):
	if response.is_html:
		try:
			res = tidy.parseString(response.content, **opts)
		except:
			sc_module.OutputQueue.put(__name__, 'Error parsing: [%s]' % request.url_string)
			return
		else:
			try:
				if len(res.errors) > 0:
					sc_module.OutputQueue.put(__name__, 'Invalid: [%s] (%d errors)' % (request.url_string, len(res.errors)))
					for err in res.errors:
						sc_module.OutputQueue.put(__name__, '\t%s' % str(err).replace('line', 'Line'))
			except:
				#File "/usr/lib/python2.6/site-packages/tidy/lib.py", line 81, in __init__
				#self.col = int(tokens[3])
				#ValueError: invalid literal for int() with base 10: 'h545'

				#File "/usr/lib/python2.6/site-packages/tidy/lib.py", line 86, in __init__
				#self.message = tokens[1]
				#IndexError: list index out of range
				return
