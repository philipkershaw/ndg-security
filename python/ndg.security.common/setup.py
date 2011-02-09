#!/usr/bin/env python

"""Distribution Utilities setup program for NDG Security Package

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "24/04/06"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

# Bootstrap setuptools if necessary.
from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages

import os, sys

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
credentialRepositoryDbSupport = False
if credentialRepositoryDbSupport:
    _pkgDependencies += [
    'SQLObject',
    'MySQL-python', # TODO: fix gcc error: unrecognized option `-restrict'
]

# Python 2.5 includes ElementTree by default
if sys.version_info[0:2] < (2, 5):
    _pkgDependencies += ['ElementTree', 'cElementTree']

_longDescription = """\
NDG Security is the security system for the UK Natural Environment Research
Council funded NERC DataGrid.  NDG Security has been developed to 
provide users with seamless access to secured resources across NDG 
participating organisations whilst at the same time providing an underlying 
system which is easy to deploy around organisation's pre-existing systems. 
NDG Security is designed around a Role Based Access Control mechanism. Cross 
organisational access to resources is enabled through bilateral trust 
agreements between participating organisations expressed through a system for 
single sign and role mapping.

NDG Security employs a web services based architecture enabling different 
combinations of components to be deployed according to a participating site's 
needs and requirements.  Resources are secured using a system of Policy
Enforcement Point (Gatekeeper) and Policy Decision Point components.  An 
Attribute Authority provides a service to query a given users attributes used
for gaining access to resources.  Session Manager and MyProxy services can be 
used for management of credentials.  NDG Security supports OpenID for Single
Sign On and can integrate into both web based and non-web based application 
client interfaces.
"""

setup(
    name =           		'ndg_security_common',
    version =        		'1.0.0',
    description =           'NERC DataGrid Security package containing common '
                            'utilities used by both server and client '
                            'packages',
    long_description =		_longDescription,
    author =         		'Philip Kershaw',
    author_email =   		'Philip.Kershaw@stfc.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'Philip.Kershaw@stfc.ac.uk',
    url =            		'http://proj.badc.rl.ac.uk/ndg/wiki/Security',
    license =               'Q Public License, version 1.0 or later',
    install_requires =		_pkgDependencies,
    dependency_links =		["http://ndg.nerc.ac.uk/dist"],
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
