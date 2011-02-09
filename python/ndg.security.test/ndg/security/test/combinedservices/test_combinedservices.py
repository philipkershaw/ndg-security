#!/usr/bin/env python
"""Test harness for NDG Session Manager SOAP client interface - makes requests 
for authentication and attribute retrieval.  Test Session Manager and Attribute
Authority services must be running for *AttCert* tests.  See README in this 
directory

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "23/02/06"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: test_sessionmanagerclient.py 4437 2008-11-18 12:34:25Z pjkersha $'
import logging


import unittest
import os
import sys
import getpass
import re
import base64
import urllib2

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_COMBINED_SRVS_UNITTEST_DIR'], 
                             file)

from ndg.security.common.sessionmanager import SessionManagerClient, \
    AttributeRequestDenied

from ndg.security.test import BaseTestCase    
from ndg.security.common.X509 import X509CertParse, X509CertRead
from ndg.security.common.wssecurity.dom import SignatureHandler as SigHdlr
from ndg.security.common.utils.configfileparsers import \
    CaseSensitiveConfigParser


class CombinedServicesTestCase(BaseTestCase):
    '''Unit tests for ndg.security.common.sessionmanager.SessionManagerClient
    - SOAP Session Manager client interface
    '''
    pemPat = "-----BEGIN CERTIFICATE-----[^\-]*-----END CERTIFICATE-----"
        
    test01Passphrase = None
    test03Passphrase = None

    def _getCertChainFromProxyCertFile(self, certChainFilePath):
        '''Read user cert and user cert from a single PEM file and put in
        a list ready for input into SignatureHandler'''               
        certChainFileTxt = open(certChainFilePath).read()
        
        pemPatRE = re.compile(CombinedServicesTestCase.pemPat, re.S)
        x509CertList = pemPatRE.findall(certChainFileTxt)
        
        signingCertChain = [X509CertParse(x509Cert) for x509Cert in \
                            x509CertList]
    
        # Expecting user cert first - move this to the end.  This will
        # be the cert used to verify the message signature
        signingCertChain.reverse()
        
        return signingCertChain

    def _httpBasicAuthReq(self, *args):
        """Utility for making a client request to the WSGI test application
        using HTTP Basic Authentication"""
        req = urllib2.Request(args[0])
        
        # username and password are optional args 2 and 3
        if len(args) == 3:
            base64String = base64.encodestring('%s:%s'%(args[1:]))[:-1]
            authHeader =  "Basic %s" % base64String
            req.add_header("Authorization", authHeader)
            
        handle = urllib2.urlopen(req)
            
        return handle.read()
        

    def setUp(self):
        super(CombinedServicesTestCase, self).setUp()

        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_COMBINED_SRVS_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_COMBINED_SRVS_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))

        self.cfgParser = CaseSensitiveConfigParser()
        cfgFilePath = jnPath(os.environ['NDGSEC_COMBINED_SRVS_UNITTEST_DIR'],
                             'test_combinedservices.cfg')
        self.cfgParser.read(cfgFilePath)
        
        self.cfg = {}
        for section in self.cfgParser.sections():
            self.cfg[section] = dict(self.cfgParser.items(section))

        try:
            sslCACertList = [X509CertRead(xpdVars(file)) for file in \
                         self.cfg['setUp']['sslCACertFilePathList'].split()]
        except KeyError:
            sslCACertList = []
        
        # Set logging
        try:
            logLevel = getattr(logging, self.cfg['setUp']['logLevel'])
        except AttributeError:
            raise AttributeError("logLevel=%s not recognised, try one of: "
                                 "CRITICAL, ERROR, WARNING, INFO, DEBUG or "
                                 "NOTSET" % self.cfg['setUp']['logLevel'])
            
        logging.basicConfig(level=logLevel)
        
        # Instantiate WS proxy
        self.clnt = SessionManagerClient(uri=self.cfg['setUp']['uri'],
                        sslPeerCertCN=self.cfg['setUp'].get('sslPeerCertCN'),
                        sslCACertList=sslCACertList,
                        cfgFileSection='wsse',
                        cfg=self.cfgParser)  
               
        self.sessID = None
        self.userX509Cert = None
        self.userPriKey = None
        self.issuingCert = None
        

    def test01Connect(self):
        """test01Connect: Connect as if acting as a browser client - 
        a session ID is returned"""
        
        username = self.cfg['test01Connect']['username']
        
        if CombinedServicesTestCase.test01Passphrase is None:
            CombinedServicesTestCase.test01Passphrase = \
                                    self.cfg['test01Connect'].get('passphrase')
        
        if not CombinedServicesTestCase.test01Passphrase:
            CombinedServicesTestCase.test01Passphrase = getpass.getpass(\
                prompt="\ntest01Connect pass-phrase for user %s: " % username)

        self.userX509Cert, self.userPriKey, self.issuingCert, self.sessID = \
            self.clnt.connect(self.cfg['test01Connect']['username'], 
                    passphrase=CombinedServicesTestCase.test01Passphrase)

        print("User '%s' connected to Session Manager:\n%s" % (username, 
                                                               self.sessID))
            
            
    def test02GetSessionStatus(self):
        """test02GetSessionStatus: check a session is alive"""
        print "\n\t" + self.test02GetSessionStatus.__doc__
        
        self.test01Connect()
        assert self.clnt.getSessionStatus(sessID=self.sessID),"Session is dead"
                
        print("User connected to Session Manager with sessID=%s" % self.sessID)

        assert not self.clnt.getSessionStatus(sessID='abc'), \
                                                "sessID=abc shouldn't exist!"
            
        print "CORRECT: sessID=abc doesn't exist"


    def test03ConnectNoCreateServerSess(self):
        """test03ConnectNoCreateServerSess: Connect without creating a session - 
        sessID should be None.  This only indicates that the username/password
        are correct.  To be of practical use the AuthNService plugin at
        the Session Manager needs to return X.509 credentials e.g.
        with MyProxy plugin."""

        username = self.cfg['test03ConnectNoCreateServerSess']['username']
        
        if CombinedServicesTestCase.test03Passphrase is None:
            CombinedServicesTestCase.test03Passphrase = \
                self.cfg['test03ConnectNoCreateServerSess'].get('passphrase')
                
        if not CombinedServicesTestCase.test03Passphrase:
            prompt="\ntest03ConnectNoCreateServerSess pass-phrase for user %s: "
            CombinedServicesTestCase.test03Passphrase = getpass.getpass(\
                                                    prompt=prompt % username)
            
        userX509Cert, userPriKey,issuingCert, sessID = \
            self.clnt.connect(username, 
                      passphrase=CombinedServicesTestCase.test03Passphrase,
                      createServerSess=False)
        
        # Expect null session ID
        assert(not sessID)
          
        print("Successfully authenticated")
            

    def test04DisconnectWithSessID(self):
        """test04DisconnectWithSessID: disconnect as if acting as a browser 
        client 
        """
        
        print "\n\t" + self.test04DisconnectWithSessID.__doc__
        self.test01Connect()
        
        self.clnt.disconnect(sessID=self.sessID)
        
        print("User disconnected from Session Manager:\n%s" % self.sessID)
            

    def test05DisconnectWithUserX509Cert(self):
        """test05DisconnectWithUserX509Cert: Disconnect as a command line client 
        """
        
        print "\n\t" + self.test05DisconnectWithUserX509Cert.__doc__
        self.test01Connect()
        
        # Use user cert / private key just obtained from connect call for
        # signature generation
        if self.issuingCert:
            self.clnt.signatureHandler.reqBinSecTokValType = 'X509PKIPathv1'
            self.clnt.signatureHandler.signingPriKey = self.userPriKey        
            self.clnt.signatureHandler.signingCertChain = (self.issuingCert,
                                                           self.userX509Cert)
            self.clnt.signatureHandler.signingCert = None
        else:
            self.clnt.signatureHandler.reqBinSecTokValType = 'X509v3'
            self.clnt.signatureHandler.signingPriKeyPwd = \
                CombinedServicesTestCase.test01Passphrase
            self.clnt.signatureHandler.signingPriKey = self.userPriKey        
            self.clnt.signatureHandler.signingCertChain = ()
            self.clnt.signatureHandler.signingCert = self.userX509Cert
            
        # user X.509 cert in signature determines ID of session to delete
        self.clnt.disconnect()
        print("User disconnected from Session Manager:\n%s"%self.userX509Cert)


    def test06GetAttCertWithSessID(self):
        """test06GetAttCertWithSessID: make an attribute request using
        a session ID as authentication credential"""

        print "\n\t" + self.test06GetAttCertWithSessID.__doc__
        thisSection = self.cfg['test06GetAttCertWithSessID']      
        self.test01Connect()
        
        attCert = self.clnt.getAttCert(sessID=self.sessID, 
                                       attributeAuthorityURI=thisSection['aaURI'])
        
        print "Attribute Certificate:\n%s" % attCert 
        attCert.filePath = xpdVars(thisSection['acOutFilePath']) 
        attCert.write() 


    def test07GetAttCertWithUserX509Cert(self):
        """test07GetAttCertWithUserX509Cert: make an attribute request using
        a user cert as authentication credential"""
        print "\n\t" + self.test07GetAttCertWithUserX509Cert.__doc__
        self.test01Connect()

        if self.issuingCert:
            self.clnt.signatureHandler.reqBinSecTokValType = 'X509PKIPathv1'
            self.clnt.signatureHandler.signingPriKeyPwd = \
                                CombinedServicesTestCase.test01Passphrase
            self.clnt.signatureHandler.signingPriKey = self.userPriKey        
            self.clnt.signatureHandler.signingCertChain = (self.issuingCert,
                                                           self.userX509Cert)
            self.clnt.signatureHandler.signingCert = None
        else:
            self.clnt.signatureHandler.reqBinSecTokValType = 'X509v3'
            self.clnt.signatureHandler.signingPriKeyPwd = \
                                CombinedServicesTestCase.test01Passphrase
            self.clnt.signatureHandler.signingPriKey = self.userPriKey        
            self.clnt.signatureHandler.signingCertChain = ()
            self.clnt.signatureHandler.signingCert = self.userX509Cert
        
        # Request an attribute certificate from an Attribute Authority 
        # using the userX509Cert returned from connect()
        
        aaURI = self.cfg['test07GetAttCertWithUserX509Cert']['aaURI']
        attCert = self.clnt.getAttCert(attributeAuthorityURI=aaURI)
          
        print("Attribute Certificate:\n%s" % attCert)  


    def test08GetAttCertFromLocalAttributeAuthority(self):
        """test08GetAttCertFromLocalAttributeAuthority: query the Attribute
        Authority running in the same server instance as the Session Manager"""

        print "\n\t" + self.test08GetAttCertFromLocalAttributeAuthority.__doc__
        self.test01Connect()
        
        attCert = self.clnt.getAttCert(sessID=self.sessID)
        
        print "Attribute Certificate:\n%s" % attCert 


    def test09WSGILocalSessionManagerInstanceConnect(self):
        """test09WSGILocalSessionManagerInstanceConnect: test a WSGI app 
        calling a Session Manager WSGI instance local to the server"""
        
        # Make a client connection to the WSGI app - authenticate with WSGI
        # basic auth.  The WSGI app calls a Session Manager WSGI running in
        # the same code stack
        thisSection = self.cfg['test09WSGILocalSessionManagerInstanceConnect']
        url = thisSection['url']
        username = thisSection['username']
        password = thisSection['passphrase']
        print("WSGI app connecting to local Session Manager instance: %s" %
              self._httpBasicAuthReq(url, username, password))


    def test10WSGILocalSessionManagerInstanceGetSessionStatus(self):
        """test10WSGILocalSessionManagerInstanceGetSessionStatus: test a WSGI 
        app calling a Session Manager WSGI instance local to the server"""
        
        # Make a client connection to the WSGI app - authenticate with WSGI
        # basic auth
        thisSection = self.cfg[
                    'test10WSGILocalSessionManagerInstanceGetSessionStatus']
        url = thisSection['url']
        username = thisSection['username']
        password = thisSection['passphrase']
        print("WSGI app connecting to local Session Manager instance: %s" %
              self._httpBasicAuthReq(url, username, password))


    def test11WSGILocalSessionManagerInstanceDisconnect(self):
        """test11WSGILocalSessionManagerInstanceDisconnect: test a WSGI app 
        calling a Session Manager WSGI instance local to the server"""
        
        # Make a client connection to the WSGI app - authenticate with WSGI
        # basic auth
        thisSection=self.cfg['test11WSGILocalSessionManagerInstanceDisconnect']
        url = thisSection['url']
        username = thisSection['username']
        password = thisSection['passphrase']
        print("WSGI app connecting to local Session Manager instance: %s" %
              self._httpBasicAuthReq(url, username, password))     


    def test12WSGILocalSessionManagerInstanceGetAttCert(self):
        """test12WSGILocalSessionManagerInstanceGetAttCert: test a WSGI app 
        calling a Session Manager WSGI instance local to the server"""
        
        # Make a client connection to the WSGI app - authenticate with WSGI
        # basic auth
        thisSection=self.cfg['test12WSGILocalSessionManagerInstanceGetAttCert']
        args = (thisSection['url'], thisSection['username'],
                thisSection['passphrase'])
        
        print("WSGI app connecting to local Session Manager instance: %s" %
              self._httpBasicAuthReq(*args))       
        

    def test13WSGILocalAttributeAuthorityInstanceGetHostInfo(self):
        """test13WSGILocalAttributeAuthorityInstanceGetHostInfo: test a WSGI 
        app calling a Attribute Authority WSGI instance local to the server"""
        
        # Make a client connection to the WSGI app - authenticate with WSGI
        # basic auth
        thisSection = self.cfg[
                        'test13WSGILocalAttributeAuthorityInstanceGetHostInfo']
        
        print("WSGI app connecting to local Attribute Authority instance: %s" %
              self._httpBasicAuthReq(thisSection['url']))       
        

    def test14WSGILocalAttributeAuthorityInstanceGetTrustedHostInfo(self):
        """test14WSGILocalAttributeAuthorityInstanceGetTrustedHostInfo: test a 
        WSGI app calling a Attribute Authority WSGI instance local to the 
        server"""
        
        # Make a client connection to the WSGI app - authenticate with WSGI
        # basic auth
        thisSection = self.cfg[
                'test14WSGILocalAttributeAuthorityInstanceGetTrustedHostInfo']
        
        print("WSGI app connecting to local Attribute Authority instance: %s" %
            self._httpBasicAuthReq(thisSection['url']+'?'+thisSection['role']))       
        

    def test15WSGILocalAttributeAuthorityInstanceGetAllHostsInfo(self):
        """test15WSGILocalAttributeAuthorityInstanceGetAllHostsInfo: test a 
        WSGI app calling a Attribute Authority WSGI instance local to the 
        server"""
        
        # Make a client connection to the WSGI app - authenticate with WSGI
        # basic auth
        thisSection = self.cfg[
                    'test15WSGILocalAttributeAuthorityInstanceGetAllHostsInfo']
        
        print("WSGI app connecting to local Attribute Authority instance: %s" %
              self._httpBasicAuthReq(thisSection['url']))       


    def test16WSGILocalAttributeAuthorityInstanceGetAttCert(self):
        """test16WSGILocalAttributeAuthorityInstanceGetAttCert: test a WSGI app 
        calling a Attribute Authority WSGI instance local to the server"""
        
        # Make a client connection to the WSGI app - authenticate with WSGI
        # basic auth
        thisSection = self.cfg[
                        'test16WSGILocalAttributeAuthorityInstanceGetAttCert']
        args = (thisSection['url'], thisSection['username'],
                thisSection['passphrase'])
        
        print("WSGI app connecting to local Attribute Authority instance: %s" %
              self._httpBasicAuthReq(*args))        


if __name__ == "__main__":
    unittest.main()        
