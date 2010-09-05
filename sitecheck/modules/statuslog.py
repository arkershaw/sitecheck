# -*- coding: utf-8 -*-
import urlparse
import sc_module

def process(request, response):
	if response.status >= 400:
		msgs = ['URL: [%s] returned [%d %s]' % (request.url_string, response.status, response.message)]
		if len(request.referrer) > 0:
			msgs.append('\tReferrer: [%s]' % request.referrer)
		sc_module.OutputQueue.put(__name__, msgs)
