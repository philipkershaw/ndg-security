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
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

import unittest
import os
import sys
import getpass
import re

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_SMCLNT_UNITTEST_DIR'], file)

from ndg.security.test import BaseTestCase

from ndg.security.common.sessionmanager import SessionManagerClient, \
    AttributeRequestDenied
    
from ndg.security.common.X509 import X509CertParse, X509CertRead
from ndg.security.common.wssecurity.dom import SignatureHandler as SigHdlr
from ndg.security.common.utils.configfileparsers import \
    CaseSensitiveConfigParser


class SessionManagerClientTestCase(BaseTestCase):
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
        
        pemPatRE = re.compile(SessionManagerClientTestCase.pemPat, re.S)
        x509CertList = pemPatRE.findall(certChainFileTxt)
        
        signingCertChain = [X509CertParse(x509Cert) for x509Cert in 
                            x509CertList]
    
        # Expecting user cert first - move this to the end.  This will
        # be the cert used to verify the message signature
        signingCertChain.reverse()
        
        return signingCertChain


        
    def setUp(self):
        super(SessionManagerClientTestCase, self).setUp()

        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_SMCLNT_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_SMCLNT_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))

        self.cfgParser = CaseSensitiveConfigParser()
        cfgFilePath = jnPath(os.environ['NDGSEC_SMCLNT_UNITTEST_DIR'],
                                'sessionMgrClientTest.cfg')
        self.cfgParser.read(cfgFilePath)
        
        self.cfg = {}
        for section in self.cfgParser.sections():
            self.cfg[section] = dict(self.cfgParser.items(section))

        try:
            sslCACertList = [X509CertRead(xpdVars(file)) for file in \
                         self.cfg['setUp']['sslCACertFilePathList'].split()]
        except KeyError:
            sslCACertList = []
            
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
        
        if SessionManagerClientTestCase.test01Passphrase is None:
            SessionManagerClientTestCase.test01Passphrase = \
                                    self.cfg['test01Connect'].get('passphrase')
        
        if not SessionManagerClientTestCase.test01Passphrase:
            SessionManagerClientTestCase.test01Passphrase = getpass.getpass(\
                prompt="\ntest01Connect pass-phrase for user %s: " % username)

        self.userX509Cert, self.userPriKey, self.issuingCert, self.sessID = \
            self.clnt.connect(self.cfg['test01Connect']['username'], 
                    passphrase=SessionManagerClientTestCase.test01Passphrase)

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
        
        if SessionManagerClientTestCase.test03Passphrase is None:
            SessionManagerClientTestCase.test03Passphrase = \
                self.cfg['test03ConnectNoCreateServerSess'].get('passphrase')
                
        if not SessionManagerClientTestCase.test03Passphrase:
            prompt="\ntest03ConnectNoCreateServerSess pass-phrase for user %s: "
            SessionManagerClientTestCase.test03Passphrase = getpass.getpass(\
                                                    prompt=prompt % username)
            
        userX509Cert, userPriKey,issuingCert, sessID = \
            self.clnt.connect(username, 
                      passphrase=SessionManagerClientTestCase.test03Passphrase,
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
                SessionManagerClientTestCase.test01Passphrase
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


    def test07GetAttCertRefusedWithSessID(self):
        """test07GetAttCertRefusedWithSessID: make an attribute request using
        a sessID as authentication credential requesting an AC from an
        Attribute Authority where the user is NOT registered"""

        print "\n\t" + self.test07GetAttCertRefusedWithSessID.__doc__        
        self.test01Connect()
        
        aaURI = self.cfg['test07GetAttCertRefusedWithSessID']['aaURI']
        
        try:
            attCert = self.clnt.getAttCert(sessID=self.sessID, 
                                           attributeAuthorityURI=aaURI,
                                           mapFromTrustedHosts=False)
        except AttributeRequestDenied, e:
            print "SUCCESS - obtained expected result: %s" % e
            return
        
        self.fail("Request allowed from AA where user is NOT registered!")


    def test08GetMappedAttCertWithSessID(self):
        """test08GetMappedAttCertWithSessID: make an attribute request using
        a session ID as authentication credential"""

        print "\n\t" + self.test08GetMappedAttCertWithSessID.__doc__        
        self.test01Connect()
        
        aaURI = self.cfg['test08GetMappedAttCertWithSessID']['aaURI']
        
        attCert=self.clnt.getAttCert(sessID=self.sessID, attributeAuthorityURI=aaURI)
        
        print "Attribute Certificate:\n%s" % attCert  


    def test09GetAttCertWithExtAttCertListWithSessID(self):
        """test09GetAttCertWithExtAttCertListWithSessID: make an attribute 
        request usinga session ID as authentication credential"""
        
        print "\n\t"+self.test09GetAttCertWithExtAttCertListWithSessID.__doc__        
        self.test01Connect()
        thisSection = self.cfg['test09GetAttCertWithExtAttCertListWithSessID']
        
        aaURI = thisSection['aaURI']
        
        # Use output from test06GetAttCertWithSessID!
        extACFilePath = xpdVars(thisSection['extACFilePath'])
        extAttCert = open(extACFilePath).read()
        
        attCert = self.clnt.getAttCert(sessID=self.sessID, 
                                       attributeAuthorityURI=aaURI,
                                       extAttCertList=[extAttCert])
          
        print("Attribute Certificate:\n%s" % attCert)  


    def test10GetAttCertWithUserX509Cert(self):
        """test10GetAttCertWithUserX509Cert: make an attribute request using
        a user cert as authentication credential"""
        print "\n\t" + self.test10GetAttCertWithUserX509Cert.__doc__
        self.test01Connect()

        if self.issuingCert:
            self.clnt.signatureHandler.reqBinSecTokValType = 'X509PKIPathv1'
            self.clnt.signatureHandler.signingPriKeyPwd = \
                                SessionManagerClientTestCase.test01Passphrase
            self.clnt.signatureHandler.signingPriKey = self.userPriKey        
            self.clnt.signatureHandler.signingCertChain = (self.issuingCert,
                                                           self.userX509Cert)
            self.clnt.signatureHandler.signingCert = None
        else:
            self.clnt.signatureHandler.reqBinSecTokValType = 'X509v3'
            self.clnt.signatureHandler.signingPriKeyPwd = \
                                SessionManagerClientTestCase.test01Passphrase
            self.clnt.signatureHandler.signingPriKey = self.userPriKey        
            self.clnt.signatureHandler.signingCertChain = ()
            self.clnt.signatureHandler.signingCert = self.userX509Cert
        
        # Request an attribute certificate from an Attribute Authority 
        # using the userX509Cert returned from connect()
        
        aaURI = self.cfg['test10GetAttCertWithUserX509Cert']['aaURI']
        attCert = self.clnt.getAttCert(attributeAuthorityURI=aaURI)
          
        print("Attribute Certificate:\n%s" % attCert)  
            
            
class SessionManagerClientTestSuite(unittest.TestSuite):
    
    def __init__(self):
        map = map(SessionManagerClientTestCase,
                  (
                    "test01Connect",
                    "test02GetSessionStatus",
                    "test03ConnectNoCreateServerSess",
                    "test04DisconnectWithSessID",
                    "test05DisconnectWithUserX509Cert",
                    "test06GetAttCertWithSessID",
                    "test08GetMappedAttCertWithSessID",
                    "test09GetAttCertWithExtAttCertListWithSessID",
                    "test10GetAttCertWithUserX509Cert",
                  ))
        unittest.TestSuite.__init__(self, map)
            
                                                    
if __name__ == "__main__":
    unittest.main()        
