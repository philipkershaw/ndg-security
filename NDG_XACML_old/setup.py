#!/usr/bin/env python

"""Distribution Utilities setup program for NDG XACML Package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "19/02/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'

# Bootstrap setuptools if necessary.
from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages

import os, sys

# Packages needed for NDG Security
# Note commented out ones fail with PyPI - use explicit link instead
# TODO: subdivide these into server and client specific and comon dependencies
_pkgDependencies = []

# Python 2.5 includes ElementTree by default
if sys.version_info[0:2] < (2, 5):
    _pkgDependencies += ['ElementTree', 'cElementTree']

_longDescription = """XACML Python implementation adapted from Sun's Java XACML
"""

setup(
    name =           		'NDG_XACML',
    version =        		'0.1',
    description =           'NERC DataGrid XACML package',
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
    namespace_packages =	['ndg'],
    # This flag will include all files under SVN control or included in
    # MANIFEST.in.
    #include_package_data =	True,
    # Finer grained control of data file inclusion can be achieved with
    # these parameters.  See the setuptools docs.
    #package_data =		{}
    #exclude_package_data =	{}
    entry_points =         None,
    test_suite =		   'ndg.xacml.test',
    zip_safe =             False
)
