# -*- coding: utf-8 -*-
from BeautifulSoup import Comment
import re
import sc_module

sentenceEnd = '!?.'
threshold = float(sc_module.get_arg(__name__, 'threshold', 45))

def process(request, response):
	if response.is_html:
		doc = sc_module.parse(response.content) #Parse again so we can modify
		if doc == None:
			sc_module.OutputQueue.put(__name__, 'ERROR: Unable to parse content [%s]' % request.url_string)
			return

		tags = doc.findAll(['script', 'style'])
		[tag.extract() for tag in tags]
		comments = doc.findAll(text=lambda text:isinstance(text, Comment))
		[comment.extract() for comment in comments]

		allText = ''
		for txt in doc.findAll(text=True):
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
			if fkre < threshold:
				sc_module.OutputQueue.put(__name__, 'Document: [%s] readability: [%f]' % (request.url_string, fkre))

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