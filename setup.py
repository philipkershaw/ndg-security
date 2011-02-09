#!/usr/bin/env python
"""Distribution Utilities setup program for MyProxy Server Utilities Package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "21/05/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = """BSD - See LICENSE file in top-level directory"""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'

# Bootstrap setuptools if necessary.
from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages

import os

setup(
    name =            	'MyProxyWebService',
    version =         	'0.1.2',
    description =     	'MyProxy Web Service',
    long_description = 	'''\
Provides a simple web service interface to MyProxy.  MyProxy is a Service for 
managing PKI based credentials which is part of the Globus Toolkit.  Providing
a HTTP based interface enables HTTP based clients to connect to a MyProxy server
and retrieve credentials.

The interface is implemented as a WSGI application which fronts a normal 
MyProxy server.  myproxy-logon and myproxy-get-trustroots are expressed as web 
service calls.  The WSGI application forwards the requests on to the MyProxy 
server over the usual MyProxy protocol.  The web service interface is RESTful 
using GET and POST operations and the logon interface makes uses of HTTP Basic 
Auth to pass username and pass-phrase credentials.  The service is hosted over 
HTTPS.

The unit tests include a test application served using paster.  Client scripts
are also available which need no specialised installation or applications, only
openssl and curl which are typically available on Linux/UNIX based systems.
    ''',
    author =          	'Philip Kershaw',
    author_email =    	'Philip.Kershaw@stfc.ac.uk',
    maintainer =        'Philip Kershaw',
    maintainer_email =  'Philip.Kershaw@stfc.ac.uk',
    url =             	'http://proj.badc.rl.ac.uk/ndg/wiki/Security/MyProxyWebService',
    platforms =         ['POSIX', 'Linux', 'Windows'],
    install_requires =  ['PasteDeploy', 
                         'PasteScript',
                         'WebOb', 
                         'MyProxyClient'],
    license =           __license__,
    test_suite =        'myproxy.server.test',
    packages =          find_packages(),
    package_data =      {
        'myproxy.server.test': [
            'README', '*.cfg', '*.ini', '*.crt', '*.key', '*.sh', 'ca/*.0'
        ]
    },
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
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
