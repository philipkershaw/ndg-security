#!/usr/bin/env python
"""Distribution Utilities setup program for NDG Security Test Package

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/03/07"
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

_pkgData = {
    'ndg.security.test.attAuthority': ['*.xml', 
                                       '*.cfg', 
                                       'test.crt',
                                       'test.key',
                                       'siteA-aa.crt',
                                       'siteA-aa.key',
                                       'siteB-aa.crt',
                                       'siteB-aa.key',
                                       'README'],
    'ndg.security.test.attAuthority.ca': ['*.crt'],
    'ndg.security.test.attCert': ['*.xml',
                                  '*.cfg',
                                  'test.crt',
                                  'test.key',
                                  'ndg-test-ca.crt',
                                  'README'],
    'ndg.security.test.ca': ['*.xml', '*.cfg', 'README'],
    'ndg.security.test.gatekeeper': ['README'],
    'ndg.security.test.Log': ['README'],
    'ndg.security.test.myProxy': ['*.xml', 
                                  '*.cfg',
                                  'user.crt',
                                  'user.key',
                                  'ndg-test-ca.crt',
                                  'openssl.conf', 
                                  'Makefile',
                                  'README'],
    'ndg.security.test.sessionCookie': ['test.crt',
                                        'test.key',
                                        'README'],
    'ndg.security.test.sessionMgr': ['*.xml', 
                                     '*.cfg', 
                                     'openssl.conf',
                                     'sm.crt',
                                     'sm.key',
                                     'user.crt',
                                     'user.key',
                                     'README'],
    'ndg.security.test.sessionMgr.ca': ['*.crt'],
    'ndg.security.test.sessionMgrClient': ['*.xml', 
                                           '*.cfg', 
                                           'openssl.conf',
                                           'sm-clnt.crt',
                                           'sm-clnt.key',
                                           'sm.crt',
                                           'sm.key',
                                           'test.crt',
                                           'test.key',
                                           'README'],
    'ndg.security.test.sessionMgrClient.ca': ['*.crt'],
    'ndg.security.test.wsSecurity': ['*.wsdl', 'README'],
    'ndg.security.test.wsSecurity.client': ['*.cfg',
                                            'clnt.crt',
                                            'clnt.key',
                                            'ndg-test-ca.crt',
                                            'Makefile'],
    'ndg.security.test.wsSecurity.server': ['*.cfg',
                                            'server.crt',
                                            'server.key',
                                            'ndg-test-ca.crt',
                                            'Makefile'],
    'ndg.security.test.X509': ['*.cfg',
                               'user.crt',
                               'proxy.crt',
                               'ndg-test-ca.crt',
                               'README'],
    'ndg.security.test.XMLSecDoc': ['*.cfg',
                                    'test.crt',
                                    'test.key',
                                    'ndg-test-ca.crt',
                                    'README']
    }    

setup(
    name =           		'ndg_security_test',
    version =        		'0.9.2',
    description =    		'NERC DataGrid Security Unit tests',
    long_description =		'Unit tests client - server side',
    author =         		'Philip Kershaw',
    author_email =   		'P.J.Kershaw@rl.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'P.J.Kershaw@rl.ac.uk',
    url =            		'http://proj.badc.rl.ac.uk/ndg/wiki/T12_Security',
    license =               'Q Public License, version 1.0 or later',
    packages =			    find_packages(),
    namespace_packages =	['ndg', 'ndg.security'],
    package_data =          _pkgData,                             
    zip_safe =              False
)
