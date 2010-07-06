# -*- coding: utf-8 -*-
import enchant
from enchant.checker import SpellChecker
from enchant.tokenize import EmailFilter, URLFilter
from BeautifulSoup import Comment
import re, urlparse, threading, os
import sc_module

spell_lock = threading.Lock()
sentenceEnd = '!?.'

if os.path.exists(sc_module.session.root + 'dict.txt'):
	sc_module.OutputQueue.put(__name__, 'Using custom dictionary [%s]' % (sc_module.session.root + 'dict.txt'))
	dctnry = enchant.DictWithPWL(sc_module.get_arg(__name__, 'dictionary', 'en_GB'), sc_module.session.root + 'dict.txt')
elif os.path.exists('dict.txt'):
	sc_module.OutputQueue.put(__name__, 'Using default custom dictionary')
	dctnry = enchant.DictWithPWL(sc_module.get_arg(__name__, 'dictionary', 'en_GB'), 'dict.txt')
else:
	sc_module.OutputQueue.put(__name__, 'No custom dictionary found')
	dctnry = enchant.Dict(sc_module.get_arg(__name__, 'dictionary', 'en_GB'))

chkr = SpellChecker(dctnry, filters=[EmailFilter, URLFilter])

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

		words = {}
		spell_lock.acquire()
		try:
			for txt in doc.findAll(text=True):
				check(txt, words)
			for txt in doc.findAll(title=True):
				check(txt['title'], words)
			for txt in doc.findAll('img', alt=True):
				check(txt['alt'], words)
			for txt in doc.findAll('title'):
				check(txt.string, words)
			for txt in doc.findAll('meta', attrs={'name': re.compile('description|keywords')}):
				check(txt['content'], words)
		finally:
			spell_lock.release()

		spErr = False
		if len(words) > 0:
			sc_module.OutputQueue.put(__name__, 'Document: [%s]' % request.url_string)
			keys = words.keys()
			keys.sort()
			for k in keys:
				sc_module.OutputQueue.put(__name__, '\tWord: [%s] x %d%s' % (words[k][0], words[k][1], words[k][2]))

def check(text, words):
	if not text: return
	t = text.strip()
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
					m = re.search('(.)?\s*\\b(' + err.word + ')\\b', t)
					if m:
						if m.start() == 0 or m.group(1) in sentenceEnd or m.group(2)[0].islower(): # First word in sentence/para or not proper noun
							st = max(m.start() - 20, 0)
							en = min(m.end() + 20, l)
							ctx = ' (' + re.sub('\t|\n', ' ', t[st:en]) + ')'
							words[w] = [err.word, 1, ctx]


##From: http://snippets.dzone.com/posts/show/4569
#def substitute_entity(match):
	#ent = match.group(3)

	#if match.group(1) == "#":
		#if match.group(2) == '':
			#return unichr(int(ent))
		#elif match.group(2) == 'x':
			#return unichr(int('0x'+ent, 16))
	#else:
		#cp = n2cp.get(ent)

		#if cp:
			#return unichr(cp)
		#else:
			#return match.group()

#def htmldecode(string):
	#entity_re = re.compile(r'&(#?)(x?)(\d{1,5}|\w{1,8});')
	#return entity_re.subn(substitute_entity, string)[0]
