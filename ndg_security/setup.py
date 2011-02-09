#!/usr/bin/env python
"""Distribution Utilities setup program for NDG Security Package

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "24/04/06"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:setup.py 4746 2009-01-06 08:25:37Z pjkersha $'

# Bootstrap setuptools if necessary.
from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages

import os

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
    name =            		'ndg_security',
    version =         		'1.5.6',
    description =     		'NERC DataGrid Security Utilities',
    long_description = 		_longDescription,
    author =          		'Philip Kershaw',
    author_email =    		'Philip.Kershaw@stfc.ac.uk',
    maintainer =          	'Philip Kershaw',
    maintainer_email =    	'Philip.Kershaw@stfc.ac.uk',
    url =             	    'http://proj.badc.rl.ac.uk/ndg/wiki/Security',
    install_requires =      ['ndg_security_client', 'ndg_security_server'],
    dependency_links =      ["http://ndg.nerc.ac.uk/dist"],
    zip_safe = False
)
