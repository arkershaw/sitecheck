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

import re
import sc_module

sentenceEnd = '!?.'
threshold = float(sc_module.get_arg(__name__, 'threshold', 45))
r_min = None
r_max = None
r_count = 0
r_total = 0

def complete():
	if r_count > 0:
		sc_module.OutputQueue.put(__name__, 'SUMMARY: Min %.2f, Max %.2f, Avg %.2f' % (r_min, r_max, r_total / r_count))

def process(request, response):
	global r_min, r_max, r_count, r_total
	if response.is_html:
		doc = sc_module.HtmlHelper(response.content)
		doc.strip_comments()
		doc.strip_element(('script', 'style'))

		allText = ''
		for txt in doc.get_text():
			if len(txt.strip()) > 0:
				allText += txt.strip()
				if allText[-1] in sentenceEnd:
					allText += ' '
				else:
					allText += '. '

		if len(allText.strip()) > 0:
			twrd = float(words(allText))
			tsnt = float(sentences(allText))
			tsyl = float(syllables(allText))
			fkre = 206.835 - 1.015 * (twrd / tsnt) - 84.6 * (tsyl / twrd)

			r_count += 1
			r_total += fkre
			if r_min == None:
				r_min = fkre
			else:
				r_min = min(r_min, fkre)
			if r_max == None:
				r_max = fkre
			else:
				r_max = max(r_max, fkre)

			if fkre < threshold:
				sc_module.OutputQueue.put(__name__, 'Document: [%s] readability: [%.2f]' % (request.url_string, fkre))

def words(text):
	return len(text.split(' '))

def sentences(text):
	s = 0
	for se in sentenceEnd:
		s += text.count(se)
	if s == 0: s = 1
	return s

def syllables(text):
	s = 0
	for w in text.split(' '):
		s += len(re.findall('[aeiou]+', w.rstrip('e')))
	if s == 0: s = 1
	return s
