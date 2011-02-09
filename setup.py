#!/usr/bin/env python
"""SAML Package 

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "10/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:$'

# Bootstrap setuptools if necessary.
from ez_setup import use_setuptools
use_setuptools()
from setuptools import setup, find_packages
import os
   

setup(
    name =           		'ndg_security_saml',
    version =        		'0.2',
    description =    		'NERC DataGrid SAML Implementation',
    long_description =		('SAML 2.0 implementation for use with NDG '
                             'Attribute Interface'),
    author =         		'Philip Kershaw',
    author_email =   		'Philip.Kershaw@stfc.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'Philip.Kershaw@stfc.ac.uk',
    url =            		'http://proj.badc.rl.ac.uk/ndg/wiki/Security',
    license =               'BSD - See LICENCE file for details',
    packages =			    find_packages(),
    namespace_packages =	[],
    include_package_data =  True,
    zip_safe =              False
)
