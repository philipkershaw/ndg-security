#!/usr/bin/env python
"""Distribution Utilities setup program for MyProxy Client Package

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "12/12/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = """LGPL

Software adapted from myproxy_logon.  - For myproxy_logon see Access Grid 
Toolkit Public License (AGTPL)

This product includes software developed by and/or derived from the Access 
Grid Project (http://www.accessgrid.org) to which the U.S. Government retains 
certain rights."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

# Bootstrap setuptools if necessary.
from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages

import os

setup(
    name =            		'MyProxyClient',
    version =         		'0.9.0',
    description =     		'MyProxy Client',
    long_description = 		'Pure Python implementation of MyProxy client interface',
    author =          		'Philip Kershaw',
    author_email =    		'Philip.Kershaw@stfc.ac.uk',
    maintainer =          	'Philip Kershaw',
    maintainer_email =    	'Philip.Kershaw@stfc.ac.uk',
    url =             	    'http://proj.badc.rl.ac.uk/ndg/wiki/Security',
    platforms =             ['POSIX', 'Linux', 'Windows'],
    install_requires =      ['M2Crypto'],
    license =               __license__,
    test_suite =            'test',
    packages =              find_packages(),
    package_data =          {
        'test': ['*.cfg', '*.conf', '*.crt', '*.key', 'README']
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)',
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
    zip_safe = True
)
