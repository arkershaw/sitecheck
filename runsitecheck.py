#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2009-2012 Andrew Kershaw

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

CONTACT_EMAIL = 'arkershaw@users.sourceforge.net'
UPDATE_URL = 'http://sitecheck.sourceforge.net/settings.js'

_sitecheck = None
_suspend_file = None

def signal_handler(signal, frame):
	if _sitecheck:
		print('\nStopping...')

		_sitecheck.end()

		print('''\ns -> Suspend
Return -> Abort''')

		char = input()
		if char.strip().lower() == 's':
			sd = _sitecheck.suspend()

			f = open(_suspend_file, 'wb')
			f.write(sd)
			f.close()

			print('Suspended')
		else:
			print('Aborted')
	else:
		print('Cancelled')

	sys.exit(0)

if __name__ == '__main__':
	from argparse import ArgumentParser
	import os
	import sys
	import re
	import urllib.parse
	import urllib.request
	import datetime
	import shutil
	import imp
	from io import StringIO
	import json
	import signal
	import time
	import math

	from sitecheck import *
	from sitecheck.core import VERSION, ensure_dir, append

	signal.signal(signal.SIGINT, signal_handler)

	print('''Sitecheck {0} Copyright (C) 2009-2012 Andrew Kershaw
({1})
This program comes with ABSOLUTELY NO WARRANTY
'''.format(VERSION, CONTACT_EMAIL))

	parser = ArgumentParser()
	parser.add_argument('-d', '--domain', dest='domain', default=None, help='The domain to spider. This can also be set in the config file.')
	parser.add_argument('-p', '--page', dest='page', default=None, help='The first page to request. This can also be set in the config file.')
	parser.add_argument('directory', help='The directory containing the configuration and output.')
	args = parser.parse_args()

	_sitecheck = SiteCheck(append(args.directory, os.sep))

	_suspend_file = _sitecheck.root_path + 'suspend.pkl'
	config_file = _sitecheck.root_path + 'config.py'
	conf = None
	if os.path.exists(config_file):
		# Load existing configuration (must be done before unpickle)
		try:
			conf = imp.load_source('savedconfig', config_file)
		except:
			sys.exit('Invalid config file found in directory.')

	if os.path.exists(_suspend_file):
		print('Resuming session...')
		try:
			f = open(_suspend_file, 'rb')
			sd = f.read()
			f.close()

			_sitecheck.resume(sd)
		except:
			sys.exit('Unable to load suspend data.')
	else:
		if conf:
			print('Loading config...')
			_sitecheck.set_session(conf.Session())
		else:
			print('Using default config...')
			_sitecheck.set_session(Session())

		if hasattr(_sitecheck.session, 'check_for_updates') and _sitecheck.session.check_for_updates:
			print('Checking for updates...')
			try:
				settings = urllib.request.urlopen(UPDATE_URL).read().decode('utf-8')
				ss = StringIO(settings)
				sd = json.load(ss)
			except:
				print('Update check failed - please notify: {0}'.format(contact_email))
			else:
				if VERSION != sd['Version']:
					print('A new version ({0}) is available at: {1} '.format(sd['Version'], sd['DownloadURL']))

		op = ''
		if args.domain:
			if re.match('^https?://', args.domain, re.IGNORECASE):
				_sitecheck.session.domain = args.domain
			else:
				_sitecheck.session.domain = 'http://{0}'.format(args.domain)
			op = urllib.parse.urlparse(_sitecheck.session.domain).netloc + os.sep

		if args.page: _sitecheck.session.page = args.page

		if len(_sitecheck.session.domain) == 0:
			sys.exit('Please supply either a domain, a config file or a suspended session.')

		if _sitecheck.session.output == None or len(_sitecheck.session.output) == 0:
			op += datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S') + os.sep

		_sitecheck.session.output = op + _sitecheck.session.output

		# Clear output directory
		od = _sitecheck.root_path + _sitecheck.session.output
		if os.path.exists(od):
			try:
				shutil.rmtree(od)
			except:
				sys.exit('Unable to clear output directory.')

		try:
			ensure_dir(od)
		except:
			sys.exit('Unable to create output directory.')

	print('\nTarget: [{0}]'.format(_sitecheck.session.domain))
	print('Output: [{0}]'.format(_sitecheck.root_path + _sitecheck.session.output))
	print('Continue [Y/n]? ', end='')
	char = input()
	if char.strip().lower() == 'n':
		print('Cancelled')
		sys.exit(0)

	_sitecheck.begin()

	# If sitecheck starts successfully then remove suspend data
	if os.path.exists(_suspend_file):
		try:
			os.remove(_suspend_file)
		except:
			print('WARNING: Unable to remove suspend data: {0}'.format(_suspend_file))

	print('Checking...')

	while True:
		if _sitecheck.is_complete():
			break
		else:
			ttl = len(_sitecheck.request_queue.urls)
			rem = _sitecheck.request_queue.qsize()
			print('Remaining: {0} (Total: {1})'.format(rem, ttl))
			time.sleep(10)

	_sitecheck.end()

	print('Completed')
