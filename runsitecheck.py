#!/usr/bin/env python3
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

	from sitecheck import *
	from sitecheck.utils import read_input, append, ensure_dir, suspend, resume

	print('''Sitecheck Copyright (C) 2009-2011 Andrew Kershaw
This program comes with ABSOLUTELY NO WARRANTY''')

	parser = ArgumentParser()
	parser.add_argument('-d', '--domain', dest='domain', default=None, help='The domain to spider. This can also be set in the config file.')
	parser.add_argument('-p', '--page', dest='page', default=None, help='The first page to request. This can also be set in the config file.')
	parser.add_argument('directory', help='The directory containing the configuration and output.')
	args = parser.parse_args()

	sc = SiteCheck(append(args.directory, os.sep))

	suspend_file = sc.root_path + 'suspend.pkl'
	config_file = sc.root_path + 'config.py'
	conf = None
	if os.path.exists(config_file):
		# Load existing configuration (must be done before unpickle)
		try:
			conf = imp.load_source('savedconfig', config_file)
		except:
			sys.exit('Invalid config file found in directory.')

	if os.path.exists(suspend_file):
		print('Resuming session...')
		try:
			resume(sc, suspend_file)
		except:
			sys.exit('Unable to load suspend data.')
	else:
		if conf:
			print('Loading config...')
			sc.set_session(conf.Session())
		else:
			# Load default configuration
			sc.set_session(Session())

		if hasattr(sc.session, 'check_for_updates') and sc.session.check_for_updates:
			try:
				settings = urllib.request.urlopen('http://sitecheck.sourceforge.net/settings.js').read().decode('utf-8')
				ss = StringIO(settings)
				sd = json.load(ss)
			except:
				print('Update check failed - please notify: arkershaw@users.sourceforge.net')
			else:
				if not SiteCheck.VERSION == sd['Version']:
					print('A new version is available. Please check: http://sourceforge.net/projects/sitecheck/files/')
				sc.session.headers['User-Agent'] = sd['User-Agent']

		op = ''
		if args.domain:
			if re.match('^http', args.domain, re.IGNORECASE):
				sc.session.domain = args.domain
			else:
				sc.session.domain = 'http://{}'.format(args.domain)
			op = urllib.parse.urlparse(sc.session.domain).netloc + os.sep

		if args.page: sc.session.page = args.page

		if len(sc.session.domain) == 0:
			sys.exit('Please supply either a domain, a config file or a suspended session.')

		if sc.session.output == None or len(sc.session.output) == 0:
			op += datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S') + os.sep

		sc.session.output = op + sc.session.output

		# Clear output directory
		od = sc.root_path + sc.session.output
		if os.path.exists(od):
			try:
				shutil.rmtree(od)
			except:
				sys.exit('Unable to clear output directory.')
		try:
			ensure_dir(od)
		except:
			sys.exit('Unable to create output directory.')

	print('\nTarget: [{}]'.format(sc.session.domain))
	print('Output: [{}]\n'.format(sc.root_path + sc.session.output))

	sc.begin()

	if os.path.exists(suspend_file):
		try:
			os.remove(suspend_file)
		except:
			print('WARNING: Unable to remove suspend data.')

	print('Checking...')
	print('''s -> Suspend
q -> Abort
Return key -> Print status''')

	susp = False
	while True:
		char = read_input()
		if char == None:
			if sc.is_complete(): break
		elif char.strip().lower() == 'q':
			break
		elif char.strip().lower() == 's':
			susp = True
			break
		else:
			print('URLs: {}, Queue: {}'.format(len(sc.request_queue.urls), sc.request_queue.qsize()))
			if sc.is_complete(): break

	if susp:
		print('Suspending...')
	else:
		print('Finishing...')

	sc.end()

	if susp:
		suspend(sc, suspend_file)
	else:
		print('URLs: {}'.format(len(sc.request_queue.urls)))

	print('Completed.')
