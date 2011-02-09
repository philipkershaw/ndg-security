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

import os

__revision__ = "$Id$"

setup(
    name =            		'ndg_security',
    version =         		'0.9.2',
    description =     		'NERC DataGrid Security Utilities',
    long_description = 		'Software for securing NDG resources',
    author =          		'Philip Kershaw',
    author_email =    		'P.J.Kershaw@rl.ac.uk',
    maintainer =          	'Philip Kershaw',
    maintainer_email =    	'P.J.Kershaw@rl.ac.uk',
    url =             	    'http://proj.badc.rl.ac.uk/ndg/wiki/T12_Security',
    install_requires =      ['ndg_security_client', 'ndg_security_server'],
    dependency_links =      ["http://ndg.nerc.ac.uk/dist"],
    zip_safe = False
)
