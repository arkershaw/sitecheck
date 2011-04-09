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

from distutils.core import setup

setup(name='sitecheck',
	version='1.0',
	description='Modular web site spider for web developers',
	author='Andrew Kershaw',
	author_email='arkershaw@users.sourceforge.net',
	url='http://sourceforge.net/projects/sitecheck/',
	packages=['sitecheck'],
	scripts=['sitecheck.py'],
	package_data={'sitecheck': ['dict.txt']},

	long_description = 'Modular web site spider for web developers. Checks for many common problems including missing documents (HTTP 400), server errors (HTTP 500), spelling mistakes, validation errors, missing meta tags and potential SQL injection/XSS.',
	download_url = 'http://sourceforge.net/projects/sitecheck/files/',
	license = 'GNU Affero General Public License v3',
	platforms = ['Any'],

	classifiers = [
		'Development Status :: 5 - Production/Stable',
		'Environment :: Console',
		'Intended Audience :: Developers',
		'Intended Audience :: System Administrators',
		'License :: OSI Approved :: GNU Affero General Public License v3',
		'Natural Language :: English',
		'Operating System :: OS Independent',
		'Programming Language :: Python :: 2.7',
		'Topic :: Internet :: WWW/HTTP :: Site Management',
		'Topic :: Internet :: WWW/HTTP :: Site Management :: Link Checking',
		'Topic :: Security',
		'Topic :: Software Development :: Libraries',
		'Topic :: Software Development :: Libraries :: Python Modules',
		'Topic :: Software Development :: Testing',
		'Topic :: System :: Archiving :: Mirroring',
		'Topic :: System :: Systems Administration',
		'Topic :: Text Processing :: Markup :: HTML'
	]
)
