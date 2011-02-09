#!/usr/bin/env python
"""Unit tests for WSGI Authorization handler

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "21/05/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import logging


import unittest
import os
from urlparse import urlunsplit

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_COMBINED_SRVS_UNITTEST_DIR'], 
                             file)
from ConfigParser import SafeConfigParser

import paste.fixture
from paste.deploy import loadapp

from ndg.security.test.unit import BaseTestCase
from ndg.security.server.wsgi import NDGSecurityMiddlewareBase
from ndg.security.server.wsgi.authz.result_handler.basic import \
    PEPResultHandlerMiddleware
from ndg.security.server.wsgi.authz.result_handler.redirect import \
    HTTPRedirectPEPResultHandlerMiddleware
from ndg.security.server.wsgi.authz import (NdgPIPMiddlewareConfigError,
                                            SamlPIPMiddlewareConfigError)
from ndg.security.common.authz.msi import Response


class RedirectFollowingAccessDenied(PEPResultHandlerMiddleware):
    
    @NDGSecurityMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        
        queryString = environ.get('QUERY_STRING', '')
        if 'admin=1' in queryString:
            # User has been rejected access to a URI requiring admin rights,
            # try redirect to the same URI minus the admin query arg, this
            # request will pass because admin rights aren't needed
            queryArgs = queryString.split('&')
            queryList = [arg for arg in queryArgs if arg != 'admin=1']
            editedQuery = '&'.join(queryList)
            redirectURI = urlunsplit(('', '', self.pathInfo, editedQuery, ''))
            return self.redirect(redirectURI)
        else:
            return super(RedirectFollowingAccessDenied, self).__call__(
                                                            environ,
                                                            start_response)

        
class TestAuthZMiddleware(object):
    '''Test Application for the Authentication handler to protect'''
    response = "Test Authorization application"
       
    def __init__(self, app_conf, **local_conf):
        pass
    
    def __call__(self, environ, start_response):
        
        if environ['PATH_INFO'] == '/test_401':
            status = "401 Unauthorized"
            
        elif environ['PATH_INFO'] == '/test_403':
            status = "403 Forbidden"
            
        elif environ['PATH_INFO'] == '/test_200':
            status = "200 OK"
            
        elif environ['PATH_INFO'] == '/test_accessDeniedToSecuredURI':
            # Nb. AuthZ middleware should intercept the request and bypass this
            # response
            status = "200 OK"
            
        elif environ['PATH_INFO'] == '/test_accessGrantedToSecuredURI':
            status = "200 OK"
        else:
            status = "404 Not found"
                
        start_response(status,
                       [('Content-length', 
                         str(len(TestAuthZMiddleware.response))),
                        ('Content-type', 'text/plain')])
        return [TestAuthZMiddleware.response]


class BeakerSessionStub(dict):
    """Emulate beaker.session session object for purposes of the unit tests
    """
    def save(self):
        pass
 
    
class NdgWSGIAuthZTestCase(BaseTestCase):
    INI_FILE = 'ndg-test.ini'
    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    def __init__(self, *args, **kwargs):
        BaseTestCase.__init__(self, *args, **kwargs)
        
        
        wsgiapp = loadapp('config:'+NdgWSGIAuthZTestCase.INI_FILE, 
                          relative_to=NdgWSGIAuthZTestCase.THIS_DIR)
        self.app = paste.fixture.TestApp(wsgiapp)
        
        self.startSiteAAttributeAuthority()
        
    def test01CatchNoBeakerSessionFound(self):
        
        # PEPFilterConfigError is raised if no beaker.session is set in 
        # environ
        try:
            response = self.app.get('/test_200')
        except NdgPIPMiddlewareConfigError, e:
            print("ok - expected: %s exception: %s" % (e.__class__, e))
       
    def test02Ensure200WithNotLoggedInAndUnsecuredURI(self):
        
        # Check the authZ middleware leaves the response alone if the URI 
        # is not matched in the policy
        
        # Simulate a beaker.session in the environ
        extra_environ={'beaker.session.ndg.security':BeakerSessionStub()}
        response = self.app.get('/test_200',
                                extra_environ=extra_environ)

    def test03Catch401WithLoggedIn(self):
        
        # Check that the application being secured can raise a HTTP 401
        # response and that this respected by the Authorization middleware
        # even though a user is set in the session
        
        extra_environ={'beaker.session.ndg.security':
                       BeakerSessionStub(username='testuser')}
        response = self.app.get('/test_401', 
                                extra_environ=extra_environ,
                                status=401)

    def test04Catch403WithLoggedIn(self):
        
        # Check that the application being secured can raise a HTTP 403
        # response and that this respected by the Authorization middleware
        # even though a user is set in the session
        
        extra_environ={'beaker.session.ndg.security':
                       BeakerSessionStub(username='testuser')}
        response = self.app.get('/test_403', 
                                extra_environ=extra_environ,
                                status=403)

    def test05Catch401WithNotLoggedInAndSecuredURI(self):
        
        # AuthZ middleware grants access because the URI requested is not 
        # targeted in the policy
        
        # AuthZ middleware checks for username key in session set by AuthN
        # handler
        extra_environ={'beaker.session.ndg.security':BeakerSessionStub()}        
        response = self.app.get('/test_accessDeniedToSecuredURI',
                                extra_environ=extra_environ,
                                status=401)
        
    def test06AccessDeniedForSecuredURI(self):
        
        # User is logged in but doesn't have the required credentials for 
        # access
        extra_environ={'beaker.session.ndg.security':
                       BeakerSessionStub(username='testuser')}
        
        response = self.app.get('/test_accessDeniedToSecuredURI',
                                extra_environ=extra_environ,
                                status=403)
        self.assert_("Insufficient privileges to access the "
                     "resource" in response)
        print response

    def test07AccessGrantedForSecuredURI(self):
        
        # User is logged in and has credentials for access to a URI secured
        # by the policy file
        extra_environ={'beaker.session.ndg.security':
                       BeakerSessionStub(username='testuser')}
        
        response = self.app.get('/test_accessGrantedToSecuredURI',
                                extra_environ=extra_environ,
                                status=200)
        self.assert_(TestAuthZMiddleware.response in response)
        print response

    def test08AccessDeniedForAdminQueryArg(self):
        
        # User is logged in but doesn't have the required credentials for 
        # access
        extra_environ={'beaker.session.ndg.security':
                       BeakerSessionStub(username='testuser')}
        
        # Try this URI with the query arg admin=1.  This will be picked up
        # by the policy as a request requiring admin rights.  The request is
        # denied as the user doesn't have these rights but this then calls
        # into play the PEP result handler defined in this module,
        # RedirectFollowingAccessDenied.  This class reinvokes the request
        # but without the admin query argument.  Access is then granted for
        # the redirected request
        response = self.app.get('/test_accessGrantedToSecuredURI',
                                params={'admin': 1},
                                extra_environ=extra_environ,
                                status=302)
        try:
            redirectResponse = response.follow(extra_environ=extra_environ)
        except paste.fixture.AppError, e:
            self.failIf(TestAuthZMiddleware.response not in response)
        print response

        
class TestAuthZMiddleware(object):
    '''Test Application for the Authentication handler to protect'''
    response = "Test Authorization application"
       
    def __init__(self, app_conf, **local_conf):
        pass
    
    def __call__(self, environ, start_response):
        
        if environ['PATH_INFO'] == '/test_401':
            status = "401 Unauthorized"
            
        elif environ['PATH_INFO'] == '/test_403':
            status = "403 Forbidden"
            
        elif environ['PATH_INFO'] == '/test_200':
            status = "200 OK"
            
        elif environ['PATH_INFO'] == '/test_accessDeniedToSecuredURI':
            # Nb. AuthZ middleware should intercept the request and bypass this
            # response
            status = "200 OK"
            
        elif environ['PATH_INFO'] == '/test_accessGrantedToSecuredURI':
            status = "200 OK"
        else:
            status = "404 Not found"
                
        start_response(status,
                       [('Content-length', 
                         str(len(TestAuthZMiddleware.response))),
                        ('Content-type', 'text/plain')])
        return [TestAuthZMiddleware.response]


class BeakerSessionStub(dict):
    """Emulate beaker.session session object for purposes of the unit tests
    """
    def save(self):
        pass
 
    
class SamlWSGIAuthZTestCase(BaseTestCase):
    INI_FILE = 'saml-test.ini'
    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    def __init__(self, *args, **kwargs):       
        BaseTestCase.__init__(self, *args, **kwargs)

        
        wsgiapp = loadapp('config:'+SamlWSGIAuthZTestCase.INI_FILE, 
                          relative_to=SamlWSGIAuthZTestCase.THIS_DIR)
        self.app = paste.fixture.TestApp(wsgiapp)
        
        self.startSiteAAttributeAuthority(withSSL=True,
            port=SamlWSGIAuthZTestCase.SITEA_SSL_ATTRIBUTEAUTHORITY_PORTNUM)
        

    def test01CatchNoBeakerSessionFound(self):
        
        # PEPFilterConfigError is raised if no beaker.session is set in 
        # environ
        try:
            response = self.app.get('/test_200')
        except SamlPIPMiddlewareConfigError, e:
            print("ok - expected: %s exception: %s" % (e.__class__, e))
       
    def test02Ensure200WithNotLoggedInAndUnsecuredURI(self):
        
        # Check the authZ middleware leaves the response alone if the URI 
        # is not matched in the policy
        
        # Simulate a beaker.session in the environ
        extra_environ={'beaker.session.ndg.security':BeakerSessionStub()}
        response = self.app.get('/test_200',
                                extra_environ=extra_environ)

    def test03Catch401WithLoggedIn(self):
        
        # Check that the application being secured can raise a HTTP 401
        # response and that this respected by the Authorization middleware
        # even though a user is set in the session
        
        extra_environ = {
            'beaker.session.ndg.security':
                BeakerSessionStub(username=SamlWSGIAuthZTestCase.OPENID_URI)
        }
        response = self.app.get('/test_401', 
                                extra_environ=extra_environ,
                                status=401)

    def test04Catch403WithLoggedIn(self):
        
        # Check that the application being secured can raise a HTTP 403
        # response and that this respected by the Authorization middleware
        # even though a user is set in the session
        
        extra_environ = {
            'beaker.session.ndg.security':
                BeakerSessionStub(username=SamlWSGIAuthZTestCase.OPENID_URI)
        }
        response = self.app.get('/test_403', 
                                extra_environ=extra_environ,
                                status=403)

    def test05Catch401WithNotLoggedInAndSecuredURI(self):
        
        # AuthZ middleware grants access because the URI requested is not 
        # targeted in the policy
        
        # AuthZ middleware checks for username key in session set by AuthN
        # handler
        extra_environ={'beaker.session.ndg.security':BeakerSessionStub()}        
        response = self.app.get('/test_accessDeniedToSecuredURI',
                                extra_environ=extra_environ,
                                status=401)
        
    def test06AccessDeniedForSecuredURI(self):
        
        # User is logged in but doesn't have the required credentials for 
        # access
        extra_environ = {
            'beaker.session.ndg.security':
                BeakerSessionStub(username=SamlWSGIAuthZTestCase.OPENID_URI)
        }
        
        response = self.app.get('/test_accessDeniedToSecuredURI',
                                extra_environ=extra_environ,
                                status=403)
        self.assert_("Insufficient privileges to access the "
                     "resource" in response)
        print response

    def test07AccessGrantedForSecuredURI(self):
        
        # User is logged in and has credentials for access to a URI secured
        # by the policy file
        extra_environ = {
            'beaker.session.ndg.security':
                BeakerSessionStub(username=SamlWSGIAuthZTestCase.OPENID_URI)
        }
        
        response = self.app.get('/test_accessGrantedToSecuredURI',
                                extra_environ=extra_environ,
                                status=200)
        self.assert_(TestAuthZMiddleware.response in response)
        print response

    def test08AccessDeniedForAdminQueryArg(self):
        
        # User is logged in but doesn't have the required credentials for 
        # access
        extra_environ = {
            'beaker.session.ndg.security':
                BeakerSessionStub(username=SamlWSGIAuthZTestCase.OPENID_URI)
        }
        
        # Try this URI with the query arg admin=1.  This will be picked up
        # by the policy as a request requiring admin rights.  The request is
        # denied as the user doesn't have these rights but this then calls
        # into play the PEP result handler defined in this module,
        # RedirectFollowingAccessDenied.  This class reinvokes the request
        # but without the admin query argument.  Access is then granted for
        # the redirected request
        response = self.app.get('/test_accessGrantedToSecuredURI',
                                params={'admin': 1},
                                extra_environ=extra_environ,
                                status=302)
        try:
            redirectResponse = response.follow(extra_environ=extra_environ)
        except paste.fixture.AppError, e:
            self.failIf(TestAuthZMiddleware.response not in response)
        print response


class PEPResultHandlerTestCase(BaseTestCase):
    INI_FILE = 'pep-result-handler-test.ini'
    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    INI_FILEPATH = jnPath(THIS_DIR, INI_FILE)
    
    def __init__(self, *arg, **kw):
        BaseTestCase.__init__(self, *arg, **kw)
        
        here_dir = os.path.dirname(os.path.abspath(__file__))
        wsgiapp = loadapp('config:'+PEPResultHandlerTestCase.INI_FILE, 
                          relative_to=PEPResultHandlerTestCase.THIS_DIR)
        self.app = paste.fixture.TestApp(wsgiapp)
        
        cfg = SafeConfigParser(dict(here=PEPResultHandlerTestCase.THIS_DIR))
        cfg.read(jnPath(PEPResultHandlerTestCase.INI_FILEPATH))
        self.redirectURI = cfg.get('filter:AuthZFilter', 
                                   'authz.pepResultHandler.redirectURI')
        
        self.startSiteAAttributeAuthority(withSSL=True,
            port=SamlWSGIAuthZTestCase.SITEA_SSL_ATTRIBUTEAUTHORITY_PORTNUM)

        
    def testRedirectPEPResultHandlerMiddleware(self):
        # User is logged in but doesn't have the required credentials for 
        # access
        extra_environ = {
            'beaker.session.ndg.security':
                BeakerSessionStub(username=PEPResultHandlerTestCase.OPENID_URI)
        }
        
        # Expecting redirect response to specified redirect URI
        response = self.app.get('/test_accessDeniedToSecuredURI',
                                extra_environ=extra_environ,
                                status=302)
        print(response)
        self.assert_(response.header_dict.get('location') == self.redirectURI)
        
if __name__ == "__main__":
    unittest.main()        
