# -*- coding: utf-8 -*-
import urlparse
import sc_module

def process(request, response):
	if response.status >= 400:
		sc_module.OutputQueue.put(__name__, 'File: [%s] returned [%d %s]' % (request.url_string, response.status, response.message))
		if len(request.referrer) > 0:
			sc_module.OutputQueue.put(__name__, '\tReferrer: [%s]' % request.referrer)
