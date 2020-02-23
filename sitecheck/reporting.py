# -*- coding: utf-8 -*-

# Copyright 2009-2020 Andrew Kershaw

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
import shutil

__all__ = ['FlatFile', 'HTML']
_ensure_dir_lock = threading.Lock()


def ensure_dir(directory):
    with _ensure_dir_lock:
        if not os.path.exists(directory):
            os.makedirs(directory)


# From: http://stackoverflow.com/questions/8906926/formatting-python-timedelta-objects
def strfdelta(tdelta, fmt):
    d = {"days": tdelta.days}
    d["hours"], rem = divmod(tdelta.seconds, 3600)
    d["minutes"], d["seconds"] = divmod(rem, 60)
    return fmt.format(**d)


def report(method):
    def inner(self, *args, **kwargs):
        rd = ReportData()
        rd.default_source = self.source
        try:
            return method(self, rd, *args, **kwargs)
        finally:
            self.sitecheck.output_queue.put_report(rd)

    return inner


class ReportData(object):
    DEFAULT_SOURCE = 'sitecheck'

    def __init__(self):
        self.messages = {}
        self.default_source = ReportData.DEFAULT_SOURCE

    def add_error(self, message, source=None):
        self._add_message(message, 'ERROR', source)

    def add_message(self, message, source=None):
        self._add_message(message, '', source)

    def add_warning(self, message, source=None):
        self._add_message(message, 'WARNING', source)

    def add_debug(self, message, source=None):
        self._add_message(message, 'DEBUG', source)

    def _add_message(self, message, level, source=None):
        if source is None or len(source) == 0:
            source = self.default_source

        if source not in self.messages:
            self.messages[source] = []

        if isinstance(message, list):
            self.messages[source].extend((level, str(m)) for m in message)
        else:
            self.messages[source].append((level, str(message)))

    def __len__(self):
        l = 0
        for src in self.messages:
            l += len(self.messages[src])
        return l

    def __iter__(self):
        for src in self.messages:
            m = self.messages[src]
            yield src, m


class OutputQueue(queue.Queue):
    def put_message(self, message, source=None, block=True, timeout=None):
        rd = ReportData()
        rd.add_message(message, source)
        queue.Queue.put(self, (None, None, rd), block, timeout)

    def put_error(self, message, source=None, block=True, timeout=None):
        rd = ReportData()
        rd.add_error(message, source)
        queue.Queue.put(self, (None, None, rd), block, timeout)

    def put_report(self, report, block=True, timeout=None):
        queue.Queue.put(self, (None, None, report), block, timeout)

    def put(self, request, response, report, block=True, timeout=None):
        queue.Queue.put(self, (request, response, report), block, timeout)


class ReportThread(threading.Thread):
    def __init__(self, sitecheck):
        super(ReportThread, self).__init__()
        self._terminate = threading.Event()

        self._reports = []
        rep = sitecheck.session.report
        if type(rep) == list or type(rep) == tuple:
            for r in rep:
                self._reports.append(r)
                r.initialise(sitecheck)
        else:
            self._reports.append(rep)
            rep.initialise(sitecheck)

        self._session = sitecheck.session
        self._output_queue = sitecheck.output_queue
        self._resume = (sitecheck._resume_data is not None)

    def end(self):
        self._terminate.set()

    def run(self):
        st = datetime.datetime.now()
        self._output_queue.put_message('Started: {0:%Y-%m-%d %H:%M:%S}'.format(st))

        for r in self._reports:
            if hasattr(r, 'begin') and not self._resume:
                r.begin()

        while not self._terminate.isSet():
            self._terminate.wait(self._session.wait_seconds)
            try:
                req, res, rep = self._output_queue.get(block=False)
            except queue.Empty:
                pass
            else:
                for r in self._reports:
                    r.write(req, res, rep)

        et = datetime.datetime.now()
        self._output_queue.put_message('Completed: {0:%Y-%m-%d %H:%M:%S}'.format(et))
        self._output_queue.put_message(strfdelta(et - st, 'Duration: {days} days {hours}:{minutes:>02}:{seconds:>02}'))

        while not self._output_queue.empty():
            req, res, rep = self._output_queue.get(block=False)
            for r in self._reports:
                r.write(req, res, rep)

        for r in self._reports:
            if hasattr(r, 'end'):
                r.end() # This should throw exception as it cannot be logged


class FlatFile(object):
    def __init__(self, directory='txt'):
        self.directory = directory
        self._outfiles = {}
        self.default_log_file = 'sitecheck'
        self.extension = '.log'
        self._debug = False
        self.root_path = ''

    def initialise(self, sitecheck):
        self.root_path = sitecheck.session.root_path + sitecheck.session.output
        if self.directory is None or len(self.directory) == 0:
            pass
        else:
            self.root_path = self.root_path + os.sep + self.directory

        if not self.root_path.endswith(os.sep):
            self.root_path = self.root_path + os.sep

        self._outfiles = {}
        self.default_log_file = 'sitecheck'
        self.extension = '.log'
        self._debug = sitecheck.session._debug

    def __getstate__(self):
        state = dict(self.__dict__)
        del state['_outfiles']
        return state

    def begin(self):
        # Clear output directory
        if os.path.exists(self.root_path):
            try:
                shutil.rmtree(self.root_path)
            except:
                raise Exception('Unable to clear output directory.')

        try:
            ensure_dir(self.root_path)
        except:
            raise Exception('Unable to create output directory.')

    def _write(self, source, messages, indent):
        fl = self._outfiles[source]
        for m in messages:
            if len(m[0]) > 0:
                if m[0] != 'DEBUG' or (self._debug):
                    fl.write('{0}{1}: {2}\n'.format(indent, m[0], m[1]))
            else:
                fl.write('{0}{1}\n'.format(indent, m[1]))

    def write(self, request, response, report):
        for src, msgs in report:
            if not src in self._outfiles:
                self._outfiles[src] = open('{0}{1}{2}'.format(self.root_path, src, self.extension), mode='a')

            if request:
                indent = '\t'
                self._outfiles[src].write('URL: [{0}]\n'.format(str(request)))
            else:
                indent = ''

            self._write(src, msgs, indent)

    def end(self):
        for fl in self._outfiles.items():
            fl[1].close()


class HTML(object):
    def __init__(self, directory='html'):
        self.directory = directory
        self._outfiles = {}
        self.default_log_file = 'sitecheck'
        self.extension = '.html'
        self.header = '<html>\n\t<body>\n'
        self.footer = '\t</body>\n<html>\n'
        self._debug = False

    def initialise(self, sitecheck):
        self.root_path = sitecheck.session.root_path + sitecheck.session.output
        if self.directory is None or len(self.directory) == 0:
            pass
        else:
            self.root_path = self.root_path + os.sep + self.directory

        if not self.root_path.endswith(os.sep):
            self.root_path = self.root_path + os.sep

        self._outfiles = {}
        self.default_log_file = 'sitecheck'
        self.extension = '.html'
        self.header = '<html>\n\t<body>\n'
        self.footer = '\t</body>\n<html>\n'
        self._debug = sitecheck.session._debug

    def __getstate__(self):
        state = self._clean_state(dict(self.__dict__))
        del state['_outfiles']
        return state

    def begin(self):
        # Clear output directory
        if os.path.exists(self.root_path):
            try:
                shutil.rmtree(self.root_path)
            except:
                raise Exception('Unable to clear output directory.')

        try:
            ensure_dir(self.root_path)
        except:
            raise Exception('Unable to create output directory.')

    def _write(self, source, messages, indent):
        fl = self._outfiles[source]
        for m in messages:
            if len(m[0]) > 0:
                if m[0] != 'DEBUG' or self._debug:
                    fl.write('{0}<li>{1}: {2}</li>\n'.format(indent, m[0], html.escape(m[1].replace('\n', '<br/>\n'))))
            else:
                fl.write('{0}<li>{1}</li>\n'.format(indent, html.escape(m[1].replace('\n', '<br/>\n'))))

    def write(self, request, response, report):
        for src, msgs in report:
            if src in self._outfiles:
                fl = self._outfiles[src]
            else:
                fl = open('{0}{1}{2}'.format(self.root_path, src, self.extension), mode='a')
                self._outfiles[src] = fl
                fl.write(self.header)
                fl.write('\t\t<h1>{0}</h1>\n'.format(html.escape(src.title())))
                fl.write('\t\t<a href="index{0}">&lt;- Back</a>\n'.format(self.extension))

            if request:
                fl.write('\t\t<p>URL: <a href="{0}">{0}</a></p>\n\t\t<ul>\n'.format(html.escape(str(request))))
                self._write(src, msgs, '\t\t\t')
                fl.write('\t\t</ul>\n')
            else:
                self._write(src, msgs, '\t\t')

    def end(self):
        ix = open('{0}index{1}'.format(self.root_path, self.extension), mode='w')
        ix.write(self.header)
        ix.write('\t\t<h1>Results</h1>\n\t\t<ul>\n')

        for fl in self._outfiles.items():
            ix.write('\t\t\t<li><a href="{0}{1}">{2}</a></li>\n'.format(html.escape(fl[0]), self.extension, html.escape(fl[0].title())))
            fl[1].write(self.footer)
            fl[1].close()

        ix.write('\t\t</ul>\n')
        ix.write(self.footer)
        ix.close()
