# -*- coding: utf-8 -*-

# Copyright 2009-2015 Andrew Kershaw

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

from sitecheck.reporting import FlatFile

#Wrapper class for compatibility
#TODO: Remove this file on next major release
class FileLogger(object):
	def __init__(self):
		print('\nWARNING: Using deprecated logging class - please update your config file.')
		print('See CHANGELOG.txt for more details.\n')
		self._report = FlatFile()

	def __getattr__(self, attr):
		return getattr(self._report, attr)
