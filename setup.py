#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Copyright 2009 Andrew Kershaw

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

from setuptools import setup

setup(name='sitecheck',
	version='0.9',
	description='Modular web site spider for web developers',
	author='Andrew Kershaw',
	url='http://sourceforge.net/projects/sitecheck/',
	packages=['sitecheck', 'sitecheck.modules'],
	data_files=[('sitecheck', ['sitecheck/LICENSE', 'sitecheck/README', 'sitecheck/dict.txt'])],
	install_requires=['pytidylib', 'pyenchant']
)
