#!/usr/bin/env python2
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
	import urlparse
	import datetime

	from sitecheck import *

	print('''Sitecheck Copyright (C) 2009-2011 Andrew Kershaw
This program comes with ABSOLUTELY NO WARRANTY''')

	parser = ArgumentParser()
	parser.add_argument('-d', '--domain', dest='domain', default=None, help='The domain to spider. This can also be set in the config file.')
	parser.add_argument('-p', '--page', dest='page', default=None, help='The first page to reqeust. This can also be set in the config file.')
	parser.add_argument('directory', help='The directory containing the configuration and output.')
	args = parser.parse_args()

	sc = SiteCheck()

	config_dir = output_dir = append(args.directory, os.sep)
	suspend_file = config_dir + 'suspend.pkl'

	if os.path.exists(suspend_file):
		print('Resuming session...')
		try:
			sc.resume(suspend_file)
		except:
			print('Unable to load suspend data.')
			sys.exit()

		try:
			os.remove(suspend_file)
		except:
			print('WARNING: Unable to remove suspend data.')
	else:
		cfp = config_dir + 'config.py'
		if os.path.exists(cfp):
			# Load existing configuration
			print('Loading config...')
			import imp
			try:
				sc.set_session(imp.load_source('config', cfp).Session())
			except:
				print('Invalid config file found in directory.')
				sys.exit()
		else:
			# Load default configuration
			sc.set_session(Session())

		if args.domain:
			if re.match('^http', args.domain, re.IGNORECASE):
				sc.session.domain = args.domain
			else:
				sc.session.domain = 'http://{}'.format(args.domain)
			output_dir = output_dir + urlparse.urlparse(sc.session.domain).netloc + os.sep

		if args.page: sc.session.page = args.page

		if len(sc.session.domain) == 0:
			print('Please supply either a domain, a config file or a suspended session.')
			sys.exit()

		if sc.session.output == None or len(sc.session.output) == 0:
			sc.session.output = output_dir + datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
		else:
			sc.session.output = append(output_dir, sc.session.output)
		ensure_dir(sc.session.output)

		sc.session._config = config_dir

	print('\nTarget: [{}]'.format(sc.session.domain))
	print('Output: [{}]\n'.format(sc.session.output))

	sc.begin()

	print('Checking...')
	print('''s -> Suspend
q -> Abort
Return key -> Print status''')

	suspend = False
	while True:
		char = read_input()
		if char == None:
			if sc.is_complete(): break
		elif char.lower() == 'q':
			break
		elif char.lower() == 's':
			suspend = True
			break
		else:
			print('URLs: {}, Queue: {}'.format(len(sc.request_queue.urls), sc.request_queue.qsize()))
			if sc.is_complete(): break

	if suspend:
		print('Suspending...')
		sc.suspend(suspend_file)
	else:
		print('Finishing...')
		sc.end()

	print('Completed.')
