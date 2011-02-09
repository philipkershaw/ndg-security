#!/usr/bin/env python
"""Distribution Utilities setup program for MyProxy Client Package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "12/12/08"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = """BSD - See LICENSE file in top-level directory

Software adapted from myproxy_logon.  - For myproxy_logon see Access Grid 
Toolkit Public License (AGTPL)

This product includes software developed by and/or derived from the Access 
Grid Project (http://www.accessgrid.org) to which the U.S. Government retains 
certain rights."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'

# Bootstrap setuptools if necessary.
from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages

import os

setup(
    name =            	'MyProxyClient',
    version =         	'1.0.0',
    description =     	'MyProxy Client',
    long_description = 	'''Pure Python implementation of MyProxy client '''
    '''interface.
    
    This version replaces M2Crypto with PyOpenSSL as the OpenSSL wrapper.
    Get trust roots is now added.  A stub for Put has been added but not 
    implemented as unfortunately the PyOpenSSL X.%09 extensions interface does
    not support the required proxyCertInfo extension required for proxy
    certificates.
    ''',
    author =          	'Philip Kershaw',
    author_email =    	'Philip.Kershaw@stfc.ac.uk',
    maintainer =        'Philip Kershaw',
    maintainer_email =  'Philip.Kershaw@stfc.ac.uk',
    url =             	'http://proj.badc.rl.ac.uk/ndg/wiki/Security/MyProxyClient',
    platforms =         ['POSIX', 'Linux', 'Windows'],
    install_requires =  ['PyOpenSSL'],
    license =           __license__,
    test_suite =        'myproxy.test',
    packages =          find_packages(),
    package_data =      {
        'myproxy.test': ['*.cfg', '*.conf', '*.crt', '*.key', 'README']
    },
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: GNU Library or Lesser General Public License (BSD)',
        'Natural Language :: English',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Distributed Computing',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    zip_safe = False
)
