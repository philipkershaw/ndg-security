#!/usr/bin/env python

"""Distribution Utilities setup program for NDG Security Package

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "24/04/06"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
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
    'M2Crypto',
    'ndg_saml',
    'ndg_xacml'
    ]

# Python 2.5 includes ElementTree by default
if sys.version_info[0:2] < (2, 5):
    _pkgDependencies += ['ElementTree', 'cElementTree']

_longDescription = """\
NDG Security package for components common to client and server side 
 
NDG Security is the security system for the UK Natural Environment Research
Council funded NERC DataGrid.  NDG Security has been developed to 
provide users with seamless federated access to secured resources across NDG 
participating organisations whilst at the same time providing an underlying 
system which is easy to deploy around organisation's pre-existing systems. 

Over the past two years the system has been developed in collaboration with the 
US DoE funded Earth System Grid project for the ESG Federation an infrastructure
under development in support of CMIP5 (Coupled Model Intercomparison Project 
Phase 5), a framework for a co-ordinated set of climate model experiments 
which will input into the forthcoming 5th IPCC Assessment Report.

NDG and ESG use a common access control architecture.  OpenID and MyProxy are 
used to support single sign on for browser based and HTTP rich client based 
applications respectively.  SAML is used for attribute query and authorisation
decision interfaces.  XACML is used as the policy engine.  NDG Security has been
re-engineered to use a filter based architecture based on WSGI enabling other 
Python WSGI based applications to be protected in a flexible manner without the 
need to modify application code.
"""

setup(
    name =           		'ndg_security_common',
    version =        		'2.0.0',
    description =           'NERC DataGrid Security package containing common '
                            'utilities used by both server and client '
                            'packages',
    long_description =		_longDescription,
    author =         		'Philip Kershaw',
    author_email =   		'Philip.Kershaw@stfc.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'Philip.Kershaw@stfc.ac.uk',
    url =            		'http://proj.badc.rl.ac.uk/ndg/wiki/Security',
    license =               'BSD - See LICENCE file for details',
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
