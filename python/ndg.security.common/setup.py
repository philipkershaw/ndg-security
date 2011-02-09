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
__revision__ = '$Id$'

# Bootstrap setuptools if necessary.
from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages

import os, sys

__revision__ = "$Id$"


# Packages needed for NDG Security
# Note commented out ones fail with PyPI - use explicit link instead
# TODO: subdivide these into server and client specific and comon dependencies
_pkgDependencies = [
    'PyXML', # include as a separate dependency to force correct download link
    'ZSI',
    '4Suite-XML',
    'pycrypto',
    'M2Crypto'
    ]

# TODO: configure an option so that database support can be set for the 
# Credential Repository.  MySQL package may need to be in its own option
# eventually
credReposDbSupport = False
if credReposDbSupport:
    _pkgDependencies += [
    'SQLObject',
    'MySQL-python', # TODO: fix gcc error: unrecognized option `-restrict'
]

# Python 2.5 includes ElementTree by default
if sys.version_info[0:2] < (2, 5):
    _pkgDependencies += ['ElementTree', 'cElementTree']

# Sledge hammer approach needed with some packages as they won't install from 
# their PyPI name - instead give explicit URLs to search.  This may cause 
# problems later!
_pkgDependencyLinks = [
    # Custom M2Crypto for use with Python MyProxy client
    "http://ndg.nerc.ac.uk/dist"
]


setup(
    name =           		'ndg_security_common',
    version =        		'0.9.2',
    description = \
'''NERC DataGrid Security virtual package containing common utilities used
noth by server and client packages''',
    long_description =		'Software for securing NDG resources',
    author =         		'Philip Kershaw',
    author_email =   		'P.J.Kershaw@rl.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'P.J.Kershaw@rl.ac.uk',
    url =            		'http://proj.badc.rl.ac.uk/ndg/wiki/T12_Security',
    license =               'Q Public License, version 1.0 or later',
    install_requires =		_pkgDependencies,
    dependency_links =		_pkgDependencyLinks,
    packages =       		find_packages(),
    namespace_packages =	['ndg', 'ndg.security'],
    # This flag will include all files under SVN control or included in
    # MANIFEST.in.
    #include_package_data =	True,
    # Finer grained control of data file inclusion can be achieved with
    # these parameters.  See the setuptools docs.
    #package_data =		{}
    #exclude_package_data =	{}
    entry_points =         None,
    test_suite =		   'ndg.security.test',
    zip_safe =             False
)
