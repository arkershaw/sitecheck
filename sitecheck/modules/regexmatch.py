# -*- coding: utf-8 -*-
import re, urlparse
import sc_module

args = sc_module.get_args(__name__)

def process(request, response):
	for rx in args.iteritems():
		inv_h = inv_b = False
		if rx[0][0] == '^':
			inv_h = True
		elif rx[0][0] == '_':
			inv_b = True
		if inv_h:
			if not rx[1].search(str(response.headers)):
				sc_module.OutputQueue.put(__name__, 'Filter: [%s] not found in [%s] (headers)' % (rx[0],  request.url_string))
		elif not inv_b:
			mtchs = rx[1].finditer(str(response.headers))
			for mtch in mtchs:
				sc_module.OutputQueue.put(__name__, 'Filter: [%s] found: [%s] in [%s] (headers)' % (rx[0], mtch.group(), request.url_string))

		if response.is_html:
			if inv_b:
				if not rx[1].search(str(response.content)):
					sc_module.OutputQueue.put(__name__, 'Filter: [%s] not found in [%s]' % (rx[0],  request.url_string))
			elif not inv_h:
				mtchs = rx[1].finditer(response.content)
				for mtch in mtchs:
					sc_module.OutputQueue.put(__name__, 'Filter: [%s] found: [%s] in [%s]' % (rx[0], mtch.group(), request.url_string))
