#!/usr/bin/env python
"""Distribution Utilities setup program for NDG Security Server Package

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

import os

__revision__ = "$Id$"

# Packages needed for NDG Security
# Note commented out ones fail with PyPI - use explicit link instead
# TODO: subdivide these into server and client specific and comon dependencies
_pkgDependencies = [
    'ndg_security_common',
    
    # Zope interface
    'zope.interface',
    
    'AuthKit'
]

# Make a script interface to MyProxy client
_entryPoints = {'console_scripts': [\
    'myproxy-client = ndg.security.server.MyProxy:main',
    'init-credrepos-db = ndg.security.server.initCredReposDb:main']
}

setup(
    name =           		'ndg_security_server',
    version =        		'0.9.2',
    description =    		'NERC DataGrid Security Services',
    long_description =		'Server side component for securing NDG resources',
    author =         		'Philip Kershaw',
    author_email =   		'P.J.Kershaw@rl.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'P.J.Kershaw@rl.ac.uk',
    url =            		'http://proj.badc.rl.ac.uk/ndg/wiki/T12_Security',
    license =               'Q Public License, version 1.0 or later',
    install_requires =		_pkgDependencies,
    
    # Set ndg.security.common dependency.  Also, sledge hammer approach needed 
    # with some packages as they won't install from their PyPI name - instead give
    # the explicit URL.  This may cause problems later!
    dependency_links = [
        "http://ndg.nerc.ac.uk/dist",
        
        # Zope Interface
        "http://www.zope.org/Products/ZopeInterface/" 
        ],

    packages =			    find_packages(),
    namespace_packages =	['ndg', 'ndg.security'],
    package_data =          {
        'ndg.security.server.conf': ['*.xml','*.py','*.tac','*.cfg','*.conf'],
        'ndg.security.server.conf.certs': ['*.crt'],
        'ndg.security.server.conf.certs.ca': ['*.crt'],                                               
        'ndg.security.server.conf.attCertLog': ['*.*'],
        # Nb. '*' is a dangerous setting.  If a sub
        # package is added it will be treated as data 
        # instead of a package
        'ndg.security.server.share': ['*'],
        'ndg.security.server.AttAuthority': ['*.sh'],
        'ndg.security.server.SessionMgr': ['*.sh'],
        'ndg.security.server.ca': ['*.sh'],
        'ndg.security.server.sso': ['*.ini', '*.cfg', '*.txt'],
        'ndg.security.server.sso.sso': ['public/*.*', 'public/layout/*.*'],
        'ndg.security.server.sso.sso.templates.ndg.security': ['*.kid']},
    entry_points =           _entryPoints,
    test_suite =		    'ndg.security.test',
    zip_safe =              False
)
