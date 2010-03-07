# -*- coding: utf-8 -*-
from enchant.checker import SpellChecker
from enchant.tokenize import EmailFilter, URLFilter
import re, urlparse, threading
import sc_module

spell_lock = threading.Lock()
chkr = SpellChecker(sc_module.get_arg(__name__, 'dictionary', 'en_GB'), filters=[EmailFilter, URLFilter])

def process(request, response):
	if response.is_html:
		doc = sc_module.parse(response.content) #Parse again so we can modify
		if doc == None:
			sc_module.OutputQueue.put(__name__, 'ERROR: Unable to parse content [%s]' % request.url_string)
			return

		tags = doc.findAll(['script', 'style'])
		[tag.extract() for tag in tags]
		enc = doc.originalEncoding
		if enc == None: enc = 'utf-8'
		ct = doc.prettify().decode(enc, 'replace')
		ct = re.sub('\t|\n', ' ', ct)
		ct = re.sub('\s+', ' ', ct)
		words = {}
		spell_lock.acquire()
		try:
			for txt in doc.findAll(text=True):
				check(txt, words)
			for txt in doc.findAll(title=True):
				check(txt['title'], words)
			for txt in doc.findAll('img', alt=True):
				check(txt['alt'], words)
		finally:
			spell_lock.release()

		if len(words) > 0:
			sc_module.OutputQueue.put(__name__, 'Document: [%s]' % request.url_string)
			cl = len(ct)
			keys = words.keys()
			keys.sort()
			for k in keys:
				m = re.search('(.)\s*\\b(' + k + ')\\b', ct, re.IGNORECASE)
				if m:
					if m.group(2).isupper(): # Abbreviation
						pass
					elif m.group(1) in '.>"' or m.group(2)[0].islower(): # First word in sentence/para or not proper noun
						st = max(m.start() - 20, 0)
						en = min(m.end() + 20, cl)
						#st = max(words[k][1] - 20, 0)
						#en = min(words[k][1] + 20, cl)
						sc_module.OutputQueue.put(__name__, '\tWord: [%s] x %d (%s))' % (words[k][0], words[k][1], ct[st:en]))
				else:
					sc_module.OutputQueue.put(__name__, '\tWord: [%s] x %d' % (words[k][0], words[k][1]))

def check(text, words):
	if len(text.strip()) > 0:
		chkr.set_text(text.strip())
		for err in chkr:
			if err.word in words:
				words[err.word.lower()][1] += 1
			else:
				words[err.word.lower()] = [err.word, 1]

#txt = re.compile('<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL).sub(' ', response.content)
#txt = re.compile('<[^>]*>', re.IGNORECASE | re.DOTALL).sub(' ',txt)
#txt = re.compile('\s+').sub(' ', txt)
#txt = htmldecode(txt)
#spell_lock.acquire()
#try:
	#chkr.set_text(txt)
	#first = True
	#for err in chkr:
		#if first:
			#sc_module.OutputQueue.put(__name__, 'Document: [' + urlparse.urlunparse(request.url) + ']')
			#first = False
		#ix = err.wordpos
		#st = max(ix - 20, 0)
		#en = min(ix + len(err.word) + 20, len(txt))
		#sc_module.OutputQueue.put(__name__, '\tWord: [' + err.word + '] (' + txt[st:en] + ')')
#finally:
	#spell_lock.release()


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
