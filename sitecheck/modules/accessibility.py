# -*- coding: utf-8 -*-
import tidy, urlparse, re
import sc_module

acc = re.compile(' - Access: \[([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\]')
ignore = set()
ignore.add('1.1.2.1') # <img> missing 'longdesc' and d-link
ignore.add('2.1.1') # ensure information not conveyed through color alone.
ignore.add('6.1.1') # style sheets require testing
ignore.add('6.2.2.2') # text equivalents require updating
ignore.add('6.3.1.1') # programmatic objects require testing (script)
ignore.add('7.1.1.1') # remove flicker (script).
ignore.add('8.1.1.1') # ensure programmatic objects are accessible (script)

#opts = sc_module.get_args(__name__)
opts = {'show-warnings': False, 'accessibility-check': 1}

def process(request, response):
	if response.is_html:
		try:
			res = tidy.parseString(response.content, **opts)
			if len(res.errors) > 0:
				sc_module.OutputQueue.put(__name__, 'Invalid: [%s] (%d errors)' % (request.url_string, len(res.errors)))
				for err in res.errors:
					mtch = acc.search(str(err))
					ign = False
					if mtch:
						txt = ''
						for grp in mtch.groups():
							if len(txt) > 0: txt += '.'
							txt += grp
							if txt in ignore:
								ign = True
								break
						if not ign: sc_module.OutputQueue.put(__name__, '\t%s' % err)
		except:
			sc_module.OutputQueue.put(__name__, 'Error parsing: [%s]' % request.url_string)
