#!/usr/bin/env python
"""Distribution Utilities setup program for NDG Security Test Package

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/03/07"
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
import os
   

setup(
    name =           		'ndg_security_test',
    version =        		'1.0.0',
    description =    		'NERC DataGrid Security Unit tests',
    long_description =		'Unit tests client - server side',
    author =         		'Philip Kershaw',
    author_email =   		'Philip.Kershaw@stfc.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'Philip.Kershaw@stfc.ac.uk',
    url =            		'http://proj.badc.rl.ac.uk/ndg/wiki/Security',
    license =               'Q Public License, version 1.0 or later',
    packages =			    find_packages(),
    namespace_packages =	['ndg', 'ndg.security'],
    include_package_data =  True,
    zip_safe =              False
)
