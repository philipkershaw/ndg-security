#!/usr/bin/env python
"""Distribution Utilities setup program for NDG Security Test Package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/03/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

# Bootstrap setuptools if necessary.
from ez_setup import use_setuptools
use_setuptools()
from setuptools import setup, find_packages
   

setup(
    name =           		'ndg_security_test',
    version =        		'1.5.9',
    description =    		'NERC DataGrid Security Unit tests',
    long_description =		'Unit tests client - server side',
    author =         		'Philip Kershaw',
    author_email =   		'Philip.Kershaw@stfc.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'Philip.Kershaw@stfc.ac.uk',
    url =            		'http://proj.badc.rl.ac.uk/ndg/wiki/Security',
    license =               'BSD - See LICENCE file for details',
    install_requires =      'PyOpenSSL', # Required for paster to run under SSL
    packages =			    find_packages(),
    namespace_packages =	['ndg', 'ndg.security'],
    include_package_data =  True,
    zip_safe =              False
)
