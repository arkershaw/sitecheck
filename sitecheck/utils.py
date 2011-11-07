# -*- coding: utf-8 -*-

# Copyright 2009-2011 Andrew Kershaw

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

import threading
import os
import html.entities
import re

# From: http://code.activestate.com/recipes/52308/
class Struct:
    def __init__(self, **kwargs): self.__dict__.update(kwargs)

def append(content, append):
	if content == None and append == None:
		return ''
	elif content == None:
		return append
	elif append == None:
		return content
	elif content.lower().endswith(append.lower()):
		return content
	else:
		return content + append

#def prepend(content, prepend):
	#if content == None and prepend == None:
		#return ''
	#if content == None:
		#return prepend
	#elif prepend == None:
		#return content
	#elif content.lower().startswith(prepend.lower()):
		#return content
	#else:
		#return prepend + content

_ensure_dir_lock = threading.Lock()
def ensure_dir(directory):
	with _ensure_dir_lock:
		if not os.path.exists(directory):
			os.makedirs(directory)

# From somewhere - need to credit
def read_input():
	class ReadInputThread(threading.Thread):
		def __init__(self):
			threading.Thread.__init__(self)
			self.input = None

		def run(self):
			try:
				self.input = input()
			except:
				pass

	it = ReadInputThread()
	it.start()
	it.join(30)
	return it.input

# From: http://effbot.org/zone/re-sub.htm#unescape-html
def html_decode(text):
    def fixup(m):
        text = m.group(0)
        if text[:2] == "&#":
            try:
                if text[:3] == "&#x":
                    return chr(int(text[3:-1], 16))
                else:
                    return chr(int(text[2:-1]))
            except ValueError:
                pass
        else:
            try:
                text = chr(html.entities.name2codepoint[text[1:-1]])
            except KeyError:
                pass
        return text
    return re.sub("&#?\w+;", fixup, text)

def suspend(sitecheck, suspend_file):
	sd = sitecheck.suspend()

	f = open(suspend_file, 'wb')
	f.write(sd)
	f.close()

def resume(sitecheck, suspend_file):
	f = open(suspend_file, 'rb')
	sd = f.read()
	f.close()

	sitecheck.resume(sd)
