#!/usr/bin/env python

"""Distribution Utilities setup program for NDG Security Package

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "24/04/06"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = "$Id$"

# Bootstrap setuptools if necessary.
from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages

import os

__revision__ = "$Id$"


_entryPoints = \
{
    'console_scripts': [\
        'ndgSessionClient = ndg.security.client.ndgSessionClient:main']
}

setup(
    name =              	'ndg_security_client',
    version =           	'0.9.2',
    description =       	'NERC DataGrid Security Utilities',
    long_description =   	'Software for securing NDG resources',
    author =            	'Philip Kershaw',
    author_email =      	'P.J.Kershaw@rl.ac.uk',
    maintainer =            'Philip Kershaw',
    maintainer_email =      'P.J.Kershaw@rl.ac.uk',
    url =               	'http://proj.badc.rl.ac.uk/ndg/wiki/T12_Security',
    license =               'Q Public License, version 1.0 or later',
    install_requires =   	['ndg_security_common'],
    dependency_links =   	["http://ndg.nerc.ac.uk/dist"],
    packages =          	find_packages(),
    namespace_packages =   	['ndg', 'ndg.security'],
    package_data =          {
        'ndg.security.client.ssoclient': ['*.ini', '*.cfg', '*.txt'],
        'ndg.security.client.ssoclient.ssoclient': ['public/*.*',
                                                    'public/layout/*.*'],
        'ndg.security.client.ssoclient.ssoclient.templates.ndg.security':
                                                   ['*.kid']},
                                                   
    # This flag will include all files under SVN control or included in
    # MANIFEST.in.
    #'include_package_data =   	True,
    # Finer grained control of data file inclusion can be achieved with
    # these parameters.  See the setuptools docs.
    #'package_data =   		{}
    #'exclude_package_data =   	{}
    entry_points =           _entryPoints,
    #'test_suite =   		   'ndg.utils.test.suite',
    zip_safe =               False
)

