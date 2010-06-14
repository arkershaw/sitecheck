#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup

setup(name='sitecheck',
	version='0.8',
	description='Modular web site spider for web developers',
	author='Andrew Kershaw',
	url='http://sourceforge.net/projects/sitecheck/',
	packages=['sitecheck', 'sitecheck.modules'],
	data_files=[('sitecheck', ['sitecheck/LICENSE', 'sitecheck/README', 'sitecheck/dict.txt'])],
	install_requires=['beautiful-soup', 'python-utidylib', 'pyenchant']
)
