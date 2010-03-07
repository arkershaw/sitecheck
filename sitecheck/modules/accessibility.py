# -*- coding: utf-8 -*-
import tidy, urlparse, re
import sc_module

def process(request, response):
	if response.is_html:
		#opts = sc_module.get_args(__name__)
		opts = {'show-warnings': False, 'accessibility-check': 1}
		try:
			res = tidy.parseString(response.content, **opts)
			if len(res.errors) > 0:
				sc_module.OutputQueue.put(__name__, 'Invalid: [%s] (%d errors)' % (request.url_string, len(res.errors)))
				for err in res.errors:
					if re.search(' - Access\: ', str(err)):
						sc_module.OutputQueue.put(__name__, '\t%s' % err)
		except:
			sc_module.OutputQueue.put(__name__, 'Error parsing: [%s]' % request.url_string)
