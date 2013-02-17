#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2009-2013 Andrew Kershaw

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
SUSPEND_FILE_NAME = 'suspend.pkl'
CONFIG_FILE_NAME = 'config.py'

_sitecheck = None

def signal_handler(signal, frame):
	if _sitecheck and _sitecheck.started:
		print('\nStopping...')

		_sitecheck.end()

		print('''\ns -> Suspend
Return -> Abort''')

		char = input()
		if char.strip().lower() == 's':
			sf = _sitecheck.session.root_path + SUSPEND_FILE_NAME

			try:
				sd = pickle.dumps(_sitecheck.suspend())
			except:
				sys.exit('An error occurred while suspending.')

			try:
				f = open(sf, 'wb')
				f.write(sd)
				f.close()
			except:
				sys.exit('Unable to write suspend data to file: {0}'.format(sf))
			else:
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
	import imp
	import json
	import signal
	import time
	import math
	import pickle
	from io import StringIO

	from sitecheck import *
	from sitecheck.core import VERSION, append, Authenticate, Request
	from sitecheck.reporting import FlatFile

	signal.signal(signal.SIGINT, signal_handler)

	parser = ArgumentParser()
	parser.add_argument('-d', '--domain', dest='domain', default=None, help='The domain to spider. This can also be set in the config file.')
	parser.add_argument('-p', '--page', dest='page', default=None, help='The first page to request. This can also be set in the config file.')
	parser.add_argument('--version', action='version', version='Sitecheck {0}'.format(VERSION))
	parser.add_argument('directory', help='The directory containing the configuration and output.')
	args = parser.parse_args()

	print('''Sitecheck {0} Copyright (C) 2009-2013 Andrew Kershaw
({1})
This program comes with ABSOLUTELY NO WARRANTY
'''.format(VERSION, CONTACT_EMAIL))

	root_path = append(args.directory, os.sep)
	suspend_file = root_path + SUSPEND_FILE_NAME
	config_file = root_path + CONFIG_FILE_NAME

	# Import before unpickling
	conf = None
	if os.path.exists(config_file):
		try:
			conf = imp.load_source('sitecheck.config', config_file)
		except:
			sys.exit('Invalid config file found in directory.')

	if os.path.exists(suspend_file):
		print('Resuming session...')
		try:
			f = open(suspend_file, 'rb')
			sd = pickle.loads(f.read())
			f.close()

			_sitecheck = SiteCheck(sd)
		except:
			sys.exit('Unable to load suspend data.')

		# Set the path again in case the suspend data has been moved
		_sitecheck.session.root_path = root_path
	else:
		if conf:
			print('Loading config...')
			session = conf.Session()
		else:
			print('Using default config...')
			session = Session()

		session.root_path = root_path

		if hasattr(session, 'check_for_updates') and session.check_for_updates:
			print('Checking for updates...')
			try:
				settings = urllib.request.urlopen(UPDATE_URL).read().decode('utf-8')
				ss = StringIO(settings)
				so = json.load(ss)
			except:
				print('Update check failed - please notify: {0}'.format(contact_email))
			else:
				if VERSION != so['Version']:
					print('A new version ({0}) is available at: {1} '.format(so['Version'], so['DownloadURL']))

		op = ''
		if args.domain:
			if re.match('^https?://', args.domain, re.IGNORECASE):
				session.domain = args.domain
			else:
				session.domain = 'http://{0}'.format(args.domain)
			op = urllib.parse.urlparse(session.domain).netloc + os.sep

		if args.page:
			session.page = args.page

		if len(session.domain) == 0:
			sys.exit('Please supply either a domain, a config file or a suspended session.')

		if session.output == None or len(session.output) == 0:
			op += datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S') + os.sep

		session.output = op + session.output

		if not hasattr(session, 'report'):
			if hasattr(session, 'logger'):
				#TODO: Remove this section on next major release
				print('\nWARNING: Using deprecated logger attribute - please update your config file.')
				print('See CHANGELOG.txt for more details.\n')
				session.report = session.logger
			else:
				session.report = FlatFile()

		if hasattr(session, 'authenticate'):
			#TODO: Remove this section on next major release
			print('\nWARNING: Using deprecated authentication attribute - please update your config file.')
			print('See CHANGELOG.txt for more details.\n')
			if not [m for m in session.modules if m.name == 'Authenticate']:
				login = []
				if len(session.authenticate.login_url) > 0:
					login.append(Request(session.authenticate.login_url))
					if len(session.authenticate.params) > 0:
						login.append(Request(session.authenticate.login_url, post_data=session.authenticate.params))

				logout = []
				if len(session.authenticate.logout_url) > 0:
					logout.append(Request(session.authenticate.logout_url))

				session.modules.append(Authenticate(login=login, logout=logout))
		
		_sitecheck = SiteCheck(session)

	# TODO: Remove this section on next major release
	if not hasattr(_sitecheck.session, 'max_requests'):
		_sitecheck.session.max_requests = 0

	print('Target: [{0}]'.format(_sitecheck.session.domain))
	print('Output: [{0}]'.format(_sitecheck.session.root_path + _sitecheck.session.output))
	print('Continue [Y/n]? ', end='')
	char = input()
	if char.strip().lower() == 'n':
		print('Cancelled')
		sys.exit(0)

	_sitecheck.begin(background=True)

	# If sitecheck starts successfully then remove suspend data
	if os.path.exists(suspend_file):
		try:
			os.remove(suspend_file)
		except:
			print('WARNING: Unable to remove suspend data: {0}'.format(suspend_file))

	print('\nChecking...')

	while True:
		if _sitecheck.complete:
			break
		else:
			ttl = len(_sitecheck.request_queue.requests)
			rem = _sitecheck.request_queue.qsize()
			print('Remaining: {0} (Total: {1})'.format(rem, ttl))
			time.sleep(10)

	_sitecheck.end()

	print('Completed ({0} URLs)'.format(str(len(_sitecheck.request_queue.urls))))

