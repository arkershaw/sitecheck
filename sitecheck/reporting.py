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

import os
import queue
import threading
import datetime
import html

__all__ = ['FlatFile', 'HTML']

# From: http://stackoverflow.com/questions/8906926/formatting-python-timedelta-objects
def strfdelta(tdelta, fmt):
	d = {"days": tdelta.days}
	d["hours"], rem = divmod(tdelta.seconds, 3600)
	d["minutes"], d["seconds"] = divmod(rem, 60)
	return fmt.format(**d)

class ReportData(object):
	DEFAULT_SOURCE = 'sitecheck'

	def __init__(self, message=None, source=None):
		self.messages = {}
		if message:
			self.add_message(message, source=source)

	def add_message(self, message, source=None):
		if source == None or len(source) == 0:
			source = ReportData.DEFAULT_SOURCE

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

class ReportThread(threading.Thread):
	def __init__(self, sitecheck):
		super(ReportThread, self).__init__()
		self._terminate = threading.Event()
		self._report = sitecheck.session.report
		self._report.initialise(sitecheck)
		self._session = sitecheck.session
		self._output_queue = sitecheck.output_queue

	def end(self):
		self._terminate.set()

	def run(self):
		st = datetime.datetime.now()
		self._output_queue.put_message('Started: {0:%Y-%m-%d %H:%M:%S}'.format(st))

		if hasattr(self._report, 'begin'):
			self._report.begin()

		while not self._terminate.isSet():
			self._terminate.wait(self._session.wait_seconds)
			try:
				req, res, rep = self._output_queue.get(block=False)
			except queue.Empty:
				pass
			else:
				self._report.write(req, res, rep)

		et = datetime.datetime.now()
		self._output_queue.put_message('Completed: {0:%Y-%m-%d %H:%M:%S}'.format(et))
		self._output_queue.put_message(strfdelta(et - st, 'Duration: {days} days {hours}:{minutes:>02}:{seconds:>02}'))

		while not self._output_queue.empty():
			req, res, rep = self._output_queue.get(block=False)
			self._report.write(req, res, rep)

		if hasattr(self._report, 'end'):
			self._report.end()

class FlatFile(object):
	def initialise(self, sitecheck):
		self.root_path = sitecheck.session.root_path + sitecheck.session.output
		self._outfiles = {}
		self.default_log_file = 'sitecheck'
		self.extension = '.log'

	def __getstate__(self):
		state = dict(self.__dict__)
		del state['_outfiles']
		return state

	def write(self, request, response, report):
		for src, msgs in report:
			if not src in self._outfiles:
				self._outfiles[src] = open('{0}{1}{2}{3}'.format(self.root_path, os.sep, src, self.extension), mode='a')

			if request:
				self._outfiles[src].write('URL: [{0}]\n'.format(str(request)))
				for m in msgs:
					self._outfiles[src].write('\t{0}\n'.format(m))
			else:
				for m in msgs:
					self._outfiles[src].write('{0}\n'.format(m))

	def end(self):
		for fl in self._outfiles.items():
			fl[1].close()

class HTML(object):
	def initialise(self, sitecheck):
		self.root_path = sitecheck.session.root_path + sitecheck.session.output
		self._outfiles = {}
		self.default_log_file = 'sitecheck'
		self.extension = '.html'
		self.header = '<html>\n\t<body>\n'
		self.footer = '\t</body>\n<html>\n'

	def __getstate__(self):
		state = self._clean_state(dict(self.__dict__))
		del state['_outfiles']
		return state

	def write(self, request, response, report):
		for src, msgs in report:
			if src in self._outfiles:
				fl = self._outfiles[src]
			else:
				fl = open('{0}{1}{2}{3}'.format(self.root_path, os.sep, src, self.extension), mode='a')
				self._outfiles[src] = fl
				fl.write(self.header)
				fl.write('\t\t<h1>{0}</h1>\n'.format(html.escape(src.title())))
				fl.write('\t\t<a href="index{0}">&lt;- Back</a>\n'.format(self.extension))

			if request:
				fl.write('\t\t<p>URL: <a href="{0}">{0}</a></p>\n\t\t<ul>\n'.format(html.escape(str(request))))
				for m in msgs:
					fl.write('\t\t\t<li>{0}</li>\n'.format(html.escape(m.replace('\n', '<br/>\n'))))
				fl.write('\t\t</ul>\n')
			else:
				for m in msgs:
					fl.write('\t\t<p>{0}</p>\n'.format(html.escape(m.replace('\n', '<br/>\n'))))

	def end(self):
		ix = open('{0}{1}index{2}'.format(self.root_path, os.sep, self.extension), mode='w')
		ix.write(self.header)
		ix.write('\t\t<h1>Results</h1>\n\t\t<ul>\n')

		for fl in self._outfiles.items():
			ix.write('\t\t\t<li><a href="{0}{1}">{2}</a></li>\n'.format(html.escape(fl[0]), self.extension, html.escape(fl[0].title())))
			fl[1].write(self.footer)
			fl[1].close()

		ix.write('\t\t</ul>\n')
		ix.write(self.footer)
		ix.close()
