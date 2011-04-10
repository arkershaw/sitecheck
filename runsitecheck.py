#!/usr/bin/env python
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
	import datetime
	import shutil
	import imp

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
			print('Invalid config file found in directory.')
			sys.exit()

	if os.path.exists(suspend_file):
		print('Resuming session...')
		try:
			resume(sc, suspend_file)
		except:
			print('Unable to load suspend data.')
			sys.exit()
	else:
		if conf:
			print('Loading config...')
			sc.set_session(conf.Session())
		else:
			# Load default configuration
			sc.set_session(Session())

		op = ''
		if args.domain:
			print('asdfadsfad')
			if re.match('^http', args.domain, re.IGNORECASE):
				sc.session.domain = args.domain
			else:
				sc.session.domain = 'http://{}'.format(args.domain)
			op = urllib.parse.urlparse(sc.session.domain).netloc + os.sep

		if args.page: sc.session.page = args.page

		if len(sc.session.domain) == 0:
			print('Please supply either a domain, a config file or a suspended session.')
			sys.exit()

		if sc.session.output == None or len(sc.session.output) == 0:
			op += datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S') + os.sep

		sc.session.output = op + sc.session.output

		# Clear output directory
		od = sc.root_path + sc.session.output
		if os.path.exists(od):
			try:
				shutil.rmtree(od)
			except:
				print('Unable to clear output directory.')
				sys.exit()
		try:
			ensure_dir(od)
		except:
			print('Unable to create output directory.')
			sys.exit()

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
		elif char.lower() == 'q':
			break
		elif char.lower() == 's':
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

	if susp: suspend(sc, suspend_file)

	print('Completed.')
