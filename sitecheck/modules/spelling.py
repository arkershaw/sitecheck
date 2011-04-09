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

import enchant
from enchant.checker import SpellChecker
from enchant.tokenize import EmailFilter, URLFilter
import re, urlparse, threading, os, sys
import sc_module

spell_lock = threading.Lock()
sentenceEnd = '!?.'

if os.path.exists(sc_module.session.root + 'dict.txt'):
	sc_module.OutputQueue.put(__name__, 'Using custom dictionary [%s]' % (sc_module.session.root + 'dict.txt'))
	dctnry = enchant.DictWithPWL(sc_module.get_arg(__name__, 'dictionary', 'en_GB'), sc_module.session.root + 'dict.txt')
elif os.path.exists(os.path.join(sys.path[0], 'dict.txt')):
	sc_module.OutputQueue.put(__name__, 'Using default custom dictionary')
	dctnry = enchant.DictWithPWL(sc_module.get_arg(__name__, 'dictionary', 'en_GB'), os.path.join(sys.path[0], 'dict.txt'))
else:
	sc_module.OutputQueue.put(__name__, 'No custom dictionary found')
	dctnry = enchant.Dict(sc_module.get_arg(__name__, 'dictionary', 'en_GB'))

chkr = SpellChecker(dctnry, filters=[EmailFilter, URLFilter])

def process(request, response):
	if response.is_html:
		doc = sc_module.HtmlHelper(response.content)
		doc.strip_comments()
		doc.strip_element(('script', 'style'))

		words = {}
		spell_lock.acquire()
		try:
			for txt in doc.get_text():
				check(txt, words)
			for txt in doc.get_attribute('title'):
				check(txt[2], words)
			for txt in doc.get_attribute('alt'):
				check(txt[2], words)
			for e in doc.get_element('meta'):
				names = [n for n in e.get_attribute('name')]
				if len(names) > 0:
					name = names[0][2].lower()
					if name == 'description' or name == 'keywords':
						content = [c for c in e.get_attribute('content')]
						if len(content) > 0:
							check(content[0][2], words)
		finally:
			spell_lock.release()

		spErr = False
		if len(words) > 0:
			msgs = ['Document: [%s]' % request.url_string]
			keys = words.keys()
			keys.sort()
			for k in keys:
				msgs.append('\tWord: [%s] x %d%s' % (words[k][0], words[k][1], words[k][2]))
			sc_module.OutputQueue.put(__name__, msgs)

def check(text, words):
	if not text: return
	t = sc_module.html_decode(text.strip().decode('utf8'))
	l = len(t)
	if l > 0:
		chkr.set_text(t)
		for err in chkr:
			if err.word[1].islower(): # Ignore abbreviations
				w = err.word.lower()
				if w in words:
					words[w][1] += 1
				else:
					ctx = ''
					m = re.search(r'(.)?\s*\b(%s)\b' % err.word, t)
					if m:
						if m.start() == 0 or m.group(1) in sentenceEnd or m.group(2)[0].islower(): # First word in sentence/para or not proper noun
							st = max(m.start() - 20, 0)
							en = min(m.end() + 20, l)
							ctx = ' (' + re.sub('\t|\n', ' ', t[st:en]) + ')'
							words[w] = [err.word, 1, ctx]
