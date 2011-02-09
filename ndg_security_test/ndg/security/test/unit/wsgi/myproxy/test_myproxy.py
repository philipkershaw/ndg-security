#!/usr/bin/env python
"""Unit tests for MyProxy Client WSGI and MyProxy logon web service interface

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "14/10/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import logging
logging.basicConfig(level=logging.DEBUG)

import os
import urllib2
import base64

import paste.fixture
from paste.deploy import loadapp

from M2Crypto import X509, RSA, EVP, m2

from ndg.security.test.unit import BaseTestCase
from ndg.security.common.utils.configfileparsers import \
    CaseSensitiveConfigParser
from ndg.security.server.wsgi.myproxy import MyProxyClientMiddleware


class TestAuthnApp(object):
    '''Test Application for the Authentication handler to protect'''
    response = "Test MyProxy Client WSGI"
    URI_CLIENT_IS_IN_ENVIRON = '/test_clientIsInEnviron'
    URI_LOGON_IS_IN_ENVIRON = '/test_logonIsInEnviron'
    URI_200_OK = '/test_200'
    
    def __init__(self, app_conf, **local_conf):
        pass
        
    def __call__(self, environ, start_response):
        response = TestAuthnApp.response
        
        if environ['PATH_INFO'] == TestAuthnApp.URI_CLIENT_IS_IN_ENVIRON:
            assert(environ[MyProxyClientMiddlewareTestCase.CLIENT_ENV_KEYNAME])
            
            response = ('Found MyProxyClient instance %r=%r' % 
                (MyProxyClientMiddlewareTestCase.CLIENT_ENV_KEYNAME,
                 environ[MyProxyClientMiddlewareTestCase.CLIENT_ENV_KEYNAME]))
            
            status = "200 OK"
            
        elif environ['PATH_INFO'] == TestAuthnApp.URI_LOGON_IS_IN_ENVIRON:
            assert(environ[
                    MyProxyClientMiddlewareTestCase.LOGON_FUNC_ENV_KEYNAME])
            
            response = ('Found MyProxyClient logon function %r=%r' % 
                (MyProxyClientMiddlewareTestCase.LOGON_FUNC_ENV_KEYNAME,
                 environ[
                    MyProxyClientMiddlewareTestCase.LOGON_FUNC_ENV_KEYNAME]))
            
            status = "200 OK"
            
        elif environ['PATH_INFO'] == TestAuthnApp.URI_200_OK:
            status = "200 OK"
        else:
            status = "404 Not found"
                
        start_response(status,
                       [('Content-length', 
                         str(len(response))),
                        ('Content-type', 'text/plain')])
        return [response]
    
    
class MyProxyClientMiddlewareTestCase(BaseTestCase):
    """Test MyProxy Client WSGI"""
    CLIENT_ENV_KEYNAME = 'myProxyClient'
    LOGON_FUNC_ENV_KEYNAME = 'logon'
    SERVICE_PORTNUM = 20443
    WGET_CMD = 'wget'
    WGET_USER_OPTNAME = '--http-user'
    WGET_PASSWD_OPTNAME = '--http-password'
    WGET_OUTPUT_OPTNAME = '--output-document'
    WGET_STDOUT = '-'
    
    def __init__(self, *args, **kwargs):
        app = TestAuthnApp({})
        self.wsgiapp = MyProxyClientMiddleware(app, {}, 
    prefix='',
    myProxyClientPrefix='client_',
    clientEnvKeyName=MyProxyClientMiddlewareTestCase.CLIENT_ENV_KEYNAME,
    logonFuncEnvKeyName=MyProxyClientMiddlewareTestCase.LOGON_FUNC_ENV_KEYNAME,
    client_hostname='localhost')
        
        self.app = paste.fixture.TestApp(self.wsgiapp)
         
        BaseTestCase.__init__(self, *args, **kwargs)

    def test01CheckForClientEnvKey(self):
        response = self.app.get(TestAuthnApp.URI_CLIENT_IS_IN_ENVIRON)
        print response

    def test02CheckForLogonFuncEnvKey(self):
        response = self.app.get(TestAuthnApp.URI_LOGON_IS_IN_ENVIRON)
        print response
    
    
class MyProxyLogonMiddlewareTestCase(BaseTestCase):
    """Test MyProxy logon web service interface"""
    SERVICE_PORTNUM = 20443
    WGET_CMD = 'wget'
    WGET_USER_OPTNAME = '--http-user'
    WGET_PASSWD_OPTNAME = '--http-password'
    WGET_OUTPUT_OPTNAME = '--output-document'
    WGET_STDOUT = '-'
    INI_FILENAME = 'test.ini'
    
    def __init__(self, *args, **kwargs):
        here_dir = os.path.dirname(os.path.abspath(__file__))
        iniFilePath = os.path.join(here_dir, 
                                   MyProxyLogonMiddlewareTestCase.INI_FILENAME)
        self.wsgiapp = loadapp('config:%s' % iniFilePath)
        self.app = paste.fixture.TestApp(self.wsgiapp)
        
        cfg = CaseSensitiveConfigParser()
        cfg.read(iniFilePath)
        self.username = cfg.get('DEFAULT', 'username')
        if cfg.has_option('DEFAULT', 'password'):
            self.password = cfg.get('DEFAULT', 'password')
        else:
            self.password = None
        
        BaseTestCase.__init__(self, *args, **kwargs)

        # Thread separate Paster based service 
        self.addService(app=self.wsgiapp, 
                        port=MyProxyLogonMiddlewareTestCase.SERVICE_PORTNUM)

    def test01PasteFixtureInvalidCredentials(self):
        username = '_test'
        password = 'test'
        
        base64String = base64.encodestring('%s:%s' % (username, password))[:-1]
        authHeader =  "Basic %s" % base64String
        headers = {'Authorization': authHeader}

        url = TestAuthnApp.URI_200_OK
        
        response = self.app.get(url, headers=headers, status=401)
        print response

    def test02PasteFixture(self):
        username = self.username
        if self.password is None:
            from getpass import getpass
            password = getpass('test02PasteFixture: MyProxy pass-phrase for '
                               '%r: ' % username)
        else:
            password = self.password
        
        base64String = base64.encodestring('%s:%s' % (username, password))[:-1]
        authHeader =  "Basic %s" % base64String
        headers = {'Authorization': authHeader}

        url = TestAuthnApp.URI_200_OK
        
        response = self.app.get(url, headers=headers)
        print response
        
    def test03Urllib2ClientGET(self):
        
        username = self.username
        if self.password is None:
            from getpass import getpass
            password = getpass('test03Urllib2ClientGET: MyProxy pass-phrase '
                               'for %r: ' % username)
        else:
            password = self.password

        url = 'http://localhost:%d/test_200' % \
            MyProxyLogonMiddlewareTestCase.SERVICE_PORTNUM
            
        req = urllib2.Request(url)
        base64String = base64.encodestring('%s:%s' % (username, password))[:-1]
        authHeader =  "Basic %s" % base64String
        req.add_header("Authorization", authHeader)
        
        handle = urllib2.urlopen(req)
        
        response = handle.read()
        print (response)
        
    def test04Urllib2ClientPOST(self):
        
        username = self.username
        if self.password is None:
            from getpass import getpass
            password = getpass('test04Urllib2ClientPOST: MyProxy pass-phrase '
                               'for %r: ' % username)
        else:
            password = self.password

        url = 'http://localhost:%d/test_200' % \
            MyProxyLogonMiddlewareTestCase.SERVICE_PORTNUM
            
        req = urllib2.Request(url)
        base64String = base64.encodestring('%s:%s' % (username, password))[:-1]
        authHeader =  "Basic %s" % base64String
        req.add_header("Authorization", authHeader)
        
        # Create key pair
        nBitsForKey = 2048
        keys = RSA.gen_key(nBitsForKey, m2.RSA_F4)
        certReq = X509.Request()
        
        # Create public key object
        pubKey = EVP.PKey()
        pubKey.assign_rsa(keys)
        
        # Add the public key to the request
        certReq.set_version(0)
        certReq.set_pubkey(pubKey)
        
        x509Name = X509.X509_Name()                        
        certReq.set_subject_name(x509Name)
        
        certReq.sign(pubKey, "md5")

        pemCertReq = certReq.as_pem()
       
        handle = urllib2.urlopen(req, data=pemCertReq)
        
        response = handle.read()
        print (response)
        
    def test05WGetClient(self):
        uri = ('http://localhost:%d/test_200' % 
                  MyProxyLogonMiddlewareTestCase.SERVICE_PORTNUM)
                  
        username = self.username
        if self.password is None:
            from getpass import getpass
            password = getpass('test04WGetClient: MyProxy pass-phrase for '
                               '%r: ' % username)
        else:
            password = self.password

        import os
        import subprocess
        cmd = "%s %s %s=%s %s=%s %s=%s" % (
            MyProxyLogonMiddlewareTestCase.WGET_CMD, 
            uri,
            MyProxyLogonMiddlewareTestCase.WGET_USER_OPTNAME,
            username,
            MyProxyLogonMiddlewareTestCase.WGET_PASSWD_OPTNAME,
            password,
            MyProxyLogonMiddlewareTestCase.WGET_OUTPUT_OPTNAME,
            MyProxyLogonMiddlewareTestCase.WGET_STDOUT)
        
        p = subprocess.Popen(cmd, shell=True)
        status = os.waitpid(p.pid, 0)
        self.failIf(status[-1] != 0, "Expecting 0 exit status for %r" % cmd)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    import unittest
    unittest.main()