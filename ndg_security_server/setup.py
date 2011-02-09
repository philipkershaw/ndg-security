#!/usr/bin/env python
"""Distribution Utilities setup program for NDG Security Server Package

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "24/04/06"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

# Bootstrap setuptools if necessary.
from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages

import os

# Other packages needed by this server package
_pkgDependencies = [
    'ndg_security_common',
    'Paste',
    'WebOb',
    'beaker',
    'AuthKit',
    'MyProxyClient'
]

_entryPoints = """
    [console_scripts] 
    myproxy-saml-assertion-cert-ext-app=ndg.security.server.myproxy.certificate_extapp.saml_attribute_assertion:CertExtConsoleApp.run

    [paste.app_factory]
    main=ndg.security.server.pylons.container.config.middleware:make_app
    [paste.app_install]
    main=pylons.util:PylonsInstaller
    [paste.paster_create_template]
    ndgsecurity_services=ndg.security.server.paster_templates.template:DefaultDeploymentTemplate
    ndgsecurity_services_with_sso=ndg.security.server.paster_templates.template:FullDeploymentTemplate
    """
   
_longDescription = """\
NDG Security Server-side components package

NDG Security is the security system for the UK Natural Environment Research
Council funded NERC DataGrid.  NDG Security has been developed to 
provide users with seamless federated access to secured resources across NDG 
participating organisations whilst at the same time providing an underlying 
system which is easy to deploy around organisation's pre-existing systems. 

Over the past two years the system has been developed in collaboration with the 
US DoE funded Earth System Grid project for the ESG Federation an infrastructure
under development in support of CMIP5 (Coupled Model Intercomparison Project 
Phase 5), a framework for a co-ordinated set of climate model experiments 
which will input into the forthcoming 5th IPCC Assessment Report.

NDG and ESG use a common access control architecture.  OpenID and MyProxy are 
used to support single sign on for browser based and HTTP rich client based 
applications respectively.  SAML is used for attribute query and authorisation
decision interfaces.  XACML is used as the policy engine.  NDG Security has been
re-engineered to use a filter based architecture based on WSGI enabling other 
Python WSGI based applications to be protected in a flexible manner without the 
need to modify application code.
"""

setup(
    name =           		'ndg_security_server',
    version =        		'2.0.0',
    description =    		'Server side components for running NERC DataGrid '
                            'Security Services',
    long_description =		_longDescription,
    author =         		'Philip Kershaw',
    author_email =   		'Philip.Kershaw@stfc.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'Philip.Kershaw@stfc.ac.uk',
    url =            		'http://proj.badc.rl.ac.uk/ndg/wiki/Security',
    license =               'BSD - See LICENCE file for details',
    install_requires =		_pkgDependencies,
    extras_require = {
        'xacml':  ["ndg_xacml"]
    },
    # Set ndg.security.common dependency
    dependency_links =      ["http://ndg.nerc.ac.uk/dist"],
    packages =			    find_packages(),
    namespace_packages =	['ndg', 'ndg.security'],
    include_package_data =  True,
    package_data = {
        'ndg.security.server.sso.sso': [
            'i18n/*/LC_MESSAGES/*.mo'
        ],
        'ndg.security.server.conf': [
            '*.xml', '*.py', '*.cfg', '*.conf'
        ],
        'ndg.security.server.share': ['*'],
        'ndg.security.server.sso': ['*.ini', '*.cfg', '*.txt'],
        'ndg.security.server.sso.sso': ['public/*.*', 'public/layout/*.*'],
        'ndg.security.server.sso.sso.badc_site': [
            'public/*.*', 
            'public/layout/*.*',
            'public/layout/logos/*.*',
            'public/layout/styles/*.*',
            'public/layout/tabs/*.*'
        ],
        'ndg.security.server.sso.sso.templates.ndg.security': ['*.kid'],
        'ndg.security.server.sso.sso.badc_site.templates.ndg.security': ['*.kid'],
        'ndg.security.server.pylons': ['*.ini', '*.cfg', '*.txt'],
        'ndg.security.server.pylons.container': [
            'public/*.*', 
            'public/layout/*.*',
            'public/js/*.*',
            'public/js/img/*.*',
            'public/js/theme/*.*',
            'public/js/yui/*.*'],
        'ndg.security.server.pylons.container.templates.ndg.security': [
            '*.kid'
        ],
        # See MANIFEST.in for ndg.security.server.paster_templates files
    },
    entry_points =           _entryPoints,
    test_suite =		    'ndg.security.test',
    zip_safe =              False
)
