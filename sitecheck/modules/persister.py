# -*- coding: utf-8 -*-

# Copyright 2009 Andrew Kershaw

# This file is part of sitecheck.

# Sitecheck is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Sitecheck is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with sitecheck. If not, see <http://www.gnu.org/licenses/>.

import os, threading, re, urllib#, pipes
import sc_module
from xml.dom.minidom import getDOMImplementation

out = sc_module.get_arg(__name__, 'output', 'output')
hdrs = sc_module.get_arg(__name__, 'headers', False)
cntnt = sc_module.get_arg(__name__, 'content', False)

def process(request, response):
	if not (hdrs or cntnt): return

	od = sc_module.session.output + '/' + out

	dr = od + '/' + request.url.netloc
	parts = request.url.path.split('/')
	if parts[-1] == '':
		parts[-1] = '__index'

	if len(parts) > 1:
		dr += '/'.join(parts[0:-1])
		fl = parts[-1]
	else:
		fl = '__index'

	if len(request.url.query) > 0: fl += '?' +  urllib.unquote_plus(request.url.query)
	fl = re.sub('([ \\/])', '\\\1', fl)

	pth = os.path.join(dr, fl)
	if os.path.exists(pth + '.hdr.xml') and os.path.exists(pth + '.html'): return

	sc_module.ensure_dir(dr)
	if hdrs:
		write_headers(response, pth + '.hdr.xml')
	if cntnt and len(response.content) > 0 and response.status < 300:
		if response.is_html and not re.search('\.html?$', pth, re.IGNORECASE):
			pth += '.html'
		write_content(response.content, pth)

def write_headers(response, outfile):
	if not os.path.exists(outfile):
		dom = getDOMImplementation()
		doc = dom.createDocument(None, 'response', None)
		doc_root = doc.documentElement

		n = doc.createElement('status')
		doc_root.appendChild(n)
		st = doc.createTextNode(str(response.status))
		n.appendChild(st)

		n = doc.createElement('message')
		doc_root.appendChild(n)
		msg = doc.createTextNode(response.message)
		n.appendChild(msg)

		n = doc.createElement('headers')
		doc_root.appendChild(n)
		hdrs = response.headers.iteritems()
		for (name, value) in hdrs:
			h = doc.createElement('header')
			h.setAttribute('name', name)
			txt = doc.createTextNode(value)
			h.appendChild(txt)
			n.appendChild(h)

		doc_root.writexml(open(outfile, 'w'), addindent='\t', newl='\r\n')
		doc_root.unlink()

def write_content(content, outfile):
	if not os.path.exists(outfile):
		open(outfile, 'w').write(content)
