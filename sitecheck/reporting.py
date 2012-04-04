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

import os
import queue
import threading
import datetime

class ReportData(object):
	DEFAULT_SOURCE = 'sitecheck'

	def __init__(self, message=None, source=None):
		self.messages = {}
		if message:
			self.add_message(message, source=source)

	def add_message(self, message, source=None):
		if source == None or len(source) == 0: source = ReportData.DEFAULT_SOURCE

		if not source in self.messages:
			self.messages[source] = []

		if isinstance(message, list):
			self.messages[source].extend(str(m) for m in message)
		else:
			self.messages[source].append(str(message))

	def __len__(self):
		l = 0
		for src in self.messages:
			l += len(self.messages[src])
		return l

	def __iter__(self):
		for src in self.messages:
			m = self.messages[src]
			yield (src, m)

class OutputQueue(queue.Queue):
	def put_message(self, message, source=None, block=True, timeout=None):
		queue.Queue.put(self, (None, None, ReportData(message, source)), block, timeout)

	def put_report(self, report, block=True, timeout=None):
		queue.Queue.put(self, (None, None, report), block, timeout)

	def put(self, request, response, report, block=True, timeout=None):
		queue.Queue.put(self, (request, response, report), block, timeout)

class ReportBase(threading.Thread):
	def __init__(self):
		super(ReportBase, self).__init__()
		self.terminate = threading.Event()

	def initialise(self, sitecheck):
		self._session = sitecheck.session
		self._output_queue = sitecheck.output_queue

	def end(self):
		self.terminate.set()

	def _get_next(self):
		try:
			req, res, rep = self._output_queue.get(block=False)
		except queue.Empty:
			self.terminate.wait(self._session.wait_seconds)
			return (None, None, [])
		else:
			return (req, res, rep)

class FlatFile(ReportBase):
	def initialise(self, sitecheck):
		super(FlatFile, self).initialise(sitecheck)
		self.root_path = sitecheck.root_path
		self._outfiles = {}
		self.default_log_file = 'sitecheck'
		self.extension = '.log'

	def _write_next(self):
		req, res, rep = self._get_next()

		for src, msgs in rep:
			if not src in self._outfiles:
				self._outfiles[src] = open('{0}{1}{2}{3}{4}'.format(self.root_path, self._session.output, os.sep, src, self.extension), mode='a')

			if req:
				self._outfiles[src].write('URL: [{0}]\n'.format(str(req)))
				for m in msgs:
					self._outfiles[src].write('\t{0}\n'.format(m))
			else:
				for m in msgs:
					self._outfiles[src].write('{0}\n'.format(m))

			#self._outfiles[src].write('\n')

	def run(self):
		st = datetime.datetime.now()
		self._output_queue.put_message('Started: {0}\n'.format(st))

		while not self.terminate.isSet():
			self._write_next()

		et = datetime.datetime.now()
		self._output_queue.put_message('\nCompleted: {0} ({1})'.format(et, str(et - st)))

		while not self._output_queue.empty():
			self._write_next()

		for fl in self._outfiles.items():
			fl[1].close()
