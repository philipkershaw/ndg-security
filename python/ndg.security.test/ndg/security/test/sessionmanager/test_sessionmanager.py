#!/usr/bin/env python
"""Test harness for NDG Session Manager - makes requests for 
authentication and attribute retrieval.  Attribute Authority services must be 
running for *AttCert* test methods.  See README in this directory for details

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/11/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)

import unittest
import os, sys, getpass, re
from ConfigParser import SafeConfigParser

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_SM_UNITTEST_DIR'], file)

from ndg.security.test import BaseTestCase

from ndg.security.common.utils.configfileparsers import \
    CaseSensitiveConfigParser
from ndg.security.common.X509 import X509CertParse
from ndg.security.server.sessionmanager import SessionManager, \
    CredentialWalletAttributeRequestDenied
from ndg.security.server.attributeauthority import AttributeAuthority


class SessionManagerTestCase(BaseTestCase):
    """Unit test case for ndg.security.server.sessionmanager.SessionManager 
    class.
    
    This class manages server side sessions"""
    
    passphrase = None
    test4Passphrase = None
    
    def setUp(self):
        super(SessionManagerTestCase, self).setUp()
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_SM_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_SM_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))
        
        self.cfg = CaseSensitiveConfigParser()
        configFilePath = jnPath(os.environ['NDGSEC_SM_UNITTEST_DIR'],
                                "sessionMgrTest.cfg")
        self.cfg.read(configFilePath)
                    
        # Initialise the Session Manager client connection
        # Omit traceFile keyword to leave out SOAP debug info
        self.propFilePath = xpdVars(self.cfg.get('setUp', 'propFilePath'))
        self.sm = SessionManager(propFilePath=self.propFilePath)

    def _connect(self):
        '''Helper method to set up connections'''
        print "Connecting to session manager..."
        section = 'DEFAULT'
        
        username = self.cfg.get(section, 'username')
        if SessionManagerTestCase.passphrase is None and \
           self.cfg.has_option(section, 'passphrase'):
            SessionManagerTestCase.passphrase=self.cfg.get(section,
                                                           'passphrase')
        
        if not SessionManagerTestCase.passphrase:
            SessionManagerTestCase.passphrase = getpass.getpass(
                            prompt="\nPass-phrase for user %s: " % username)

        print("Connecting to session manager as user: %s..." % username)
        userX509Cert, userPriKey, issuingCert, self.sessID = \
            self.sm.connect(username=username, 
                            passphrase=SessionManagerTestCase.passphrase)

        print("User '%s' connected to Session Manager:\n%s" % (username, 
                                                               self.sessID))
        print("Finished setting up connection")

    def _connect2UserX509CertAuthNService(self):
        '''Same as _connect but Session Manager is using an Authentication 
        Service that returns PKI credentials i.e. like MyProxy'''
        
        section = 'DEFAULT'

        print("Connecting to session manager with AuthN service returning "
              "PKI creds...")
               
        # Change to alternative authentication service
        userX509CertFilePath = self.cfg.get(section, 'userX509CertFilePath')
        userPriKeyFilePath = self.cfg.get(section, 'userPriKeyFilePath')
        userPriKeyPwd = self.cfg.get(section, 'userPriKeyPwd')
                                          
        self.sm['authNService'] = {
            'moduleFilePath': os.environ['NDGSEC_SM_UNITTEST_DIR'],
            'moduleName': 'userx509certauthn',
            'className': 'UserX509CertAuthN',
            'userX509CertFilePath': userX509CertFilePath,
            'userPriKeyFilePath': userPriKeyFilePath
        }

        self.sm.initAuthNService()
        
        username = self.cfg.get(section, 'username')
        if SessionManagerTestCase.passphrase is None and \
           self.cfg.has_option(section, 'passphrase'):
            SessionManagerTestCase.passphrase=self.cfg.get(section, 
                                                           'passphrase')
        
        if not SessionManagerTestCase.passphrase:
            SessionManagerTestCase.passphrase = getpass.getpass(\
                prompt="\nPass-phrase for user %s: " % username)

        print("Connecting to session manager as user: %s..." % username)
        userX509Cert, self.userPriKey, self.issuingCert, self.sessID = \
            self.sm.connect(username=username, 
                            passphrase=SessionManagerTestCase.passphrase)
        self.userX509Cert = X509CertParse(userX509Cert)
        
        print("User '%s' connected to Session Manager:\n%s" % (username, 
                                                               self.sessID))
        print("Finished setting up connection")
   
    def test01Connect2AuthNServiceWithNoUserX509CertReturned(self):
        
        thisSection = 'test01Connect2AuthNServiceWithNoUserX509CertReturned'
        username = self.cfg.get(thisSection, 'username')
        if SessionManagerTestCase.passphrase is None and \
           self.cfg.has_option(thisSection, 'passphrase'):
            SessionManagerTestCase.passphrase=self.cfg.get(thisSection, 
                                                           'passphrase')
        
        if not SessionManagerTestCase.passphrase:
            SessionManagerTestCase.passphrase = getpass.getpass(
                prompt="\ntest1Connect pass-phrase for user %s: " % username)

        print "Connecting to session manager as user: %s..." %username
        userX509Cert, userPriKey, issuingCert, sessID = self.sm.connect(
                                username=username, 
                                passphrase=SessionManagerTestCase.passphrase)
        assert(userX509Cert is None)
        assert(userPriKey is None)
        assert(issuingCert is None)
        
        print("User '%s' connected to Session Manager:\n%s"%(username, sessID))     
                                  
    def test02Connect2AuthNServiceReturningAUserX509Cert(self):
        
        section = 'test02Connect2AuthNServiceReturningAUserX509Cert'
        
        # Change to alternative authentication service
        userX509CertFilePath = self.cfg.get('DEFAULT', 'userX509CertFilePath')
        userPriKeyFilePath = self.cfg.get('DEFAULT', 'userPriKeyFilePath')
        userPriKeyPwd = self.cfg.get('DEFAULT', 'userPriKeyPwd')
        outputCredFilePath = self.cfg.get(section, 'outputCredsFilePath')
                                          
        self.sm['authNService'] = {
            'moduleFilePath': os.environ['NDGSEC_SM_UNITTEST_DIR'],
            'moduleName': 'userx509certauthn',
            'className': 'UserX509CertAuthN',
            'userX509CertFilePath': userX509CertFilePath,
            'userPriKeyFilePath': userPriKeyFilePath
        }

        self.sm.initAuthNService()
        
        print("Connecting to session manager...")
        userX509Cert, self.userPriKey, self.issuingCert, sessID = self.sm.connect(
                                                    passphrase=userPriKeyPwd)
        self.userX509Cert = X509CertParse(userX509Cert)
        
        print("Connected to Session Manager:\n%s" % sessID)
        creds='\n'.join((self.issuingCert or '',
                         self.userX509Cert.asPEM().strip(),
                         self.userPriKey))
        open(mkPath(outputCredFilePath), "w").write(creds)
    
            
    def test03GetSessionStatus(self):
        """test03GetSessionStatus: check a session is alive"""
        
        self._connect()
        assert self.sm.getSessionStatus(sessID=self.sessID), "Session is dead"
        print "User connected to Session Manager with sessID=%s" % self.sessID

        assert not self.sm.getSessionStatus(sessID='abc'), \
            "sessID=abc shouldn't exist!"
            
        print "CORRECT: sessID=abc doesn't exist"
        
    def test04ConnectNoCreateServerSess(self):
        """test04ConnectNoCreateServerSess: Connect to retrieve credentials
        only - no session is created.  This makes sense only for an AuthN
        Service that returns user credentials"""
        section = 'test04ConnectNoCreateServerSess'
        
        # Change to alternative authentication service
        userX509CertFilePath = self.cfg.get('DEFAULT', 'userX509CertFilePath')
        userPriKeyFilePath = self.cfg.get('DEFAULT', 'userPriKeyFilePath')
        userPriKeyPwd = self.cfg.get('DEFAULT', 'userPriKeyPwd')
                                          
        self.sm['authNService'] = {
            'moduleFilePath': os.environ['NDGSEC_SM_UNITTEST_DIR'],
            'moduleName': 'userx509certauthn',
            'className': 'UserX509CertAuthN',
            'userX509CertFilePath': userX509CertFilePath,
            'userPriKeyFilePath': userPriKeyFilePath
        }

        self.sm.initAuthNService()
        
        
        username = self.cfg.get(section, 'username')

        if SessionManagerTestCase.test4Passphrase is None and \
           self.cfg.has_option(section, 'passphrase'):
            SessionManagerTestCase.test4Passphrase = self.cfg.get(section, 
                                                                  'passphrase')
        
        if not SessionManagerTestCase.test4Passphrase:
            SessionManagerTestCase.test4Passphrase = getpass.getpass(prompt=\
                                            "\n%s pass-phrase for user %s: " % 
                                            (section, username))

        userX509Cert, userPriKey, issuingCert, sessID = \
            self.sm.connect(username=username, 
                            passphrase=SessionManagerTestCase.test4Passphrase,
                            createServerSess=False)
        
        # Expect null session ID
        assert not sessID, "Expecting a null session ID!"
          
        print("User '%s' retrieved creds. from Session Manager:\n%s" % 
                                                    (username, sessID))
            

    def test05DisconnectWithSessID(self):
        """test05DisconnectWithSessID: disconnect as if acting as a browser 
        client 
        """
        
        self._connect()        
        self.sm.deleteUserSession(sessID=self.sessID)
        
        print "User disconnected from Session Manager:\n%s" % self.sessID
            

    def test06DisconnectWithUserX509Cert(self):
        """test5DisconnectWithUserX509Cert: Disconnect based on a user X.509
        cert. credential from an earlier call to connect 
        """
        
        self._connect2UserX509CertAuthNService()
        
        # User cert DN determines ID of session to delete
        self.sm.deleteUserSession(userX509Cert=self.userX509Cert)
        print "User disconnected from Session Manager:\n%s" % self.userX509Cert


    def test07GetAttCertWithSessID(self):
        """test07GetAttCertWithSessID: make an attribute request using
        a session ID as authentication credential"""

        self._connect()
        
        section = 'test07GetAttCertWithSessID'
        aaURI = self.cfg.get(section, 'aaURI')
        attCert = self.sm.getAttCert(sessID=self.sessID, 
                                     attributeAuthorityURI=aaURI)
        print("Attribute Certificate:\n%s" % attCert) 
        attCert.filePath = xpdVars(self.cfg.get(section, 'acOutputFilePath')) 
        attCert.write()


    def test08GetAttCertRefusedWithSessID(self):
        """test08GetAttCertRefusedWithSessID: make an attribute request using
        a sessID as authentication credential requesting an AC from an
        Attribute Authority where the user is NOT registered"""

        self._connect()
        
        aaURI = self.cfg.get('test08GetAttCertRefusedWithSessID', 'aaURI')
        
        try:
            attCert = self.sm.getAttCert(sessID=self.sessID, 
                                         attributeAuthorityURI=aaURI,
                                         mapFromTrustedHosts=False)
        except CredentialWalletAttributeRequestDenied, e:
            print("SUCCESS - obtained expected result: %s" % e)
            return
        
        self.fail("Request allowed from AA where user is NOT registered!")


    def test09GetMappedAttCertWithSessID(self):
        """test09GetMappedAttCertWithSessID: make an attribute request using
        a session ID as authentication credential"""

        self._connect()
        
        # Attribute Certificate cached in test 6 can be used to get a mapped
        # AC for this test ...
        self.test07GetAttCertWithSessID()

        aaURI = self.cfg.get('test09GetMappedAttCertWithSessID', 'aaURI')
        
        attCert = self.sm.getAttCert(sessID=self.sessID,
                                     attributeAuthorityURI=aaURI,
                                     mapFromTrustedHosts=True)
            
        print("Attribute Certificate:\n%s" % attCert)  


    def test10GetAttCertWithExtAttCertListWithSessID(self):
        """test10GetAttCertWithExtAttCertListWithSessID: make an attribute 
        request using a session ID as authentication credential"""
        
        self._connect()
        section = 'test10GetAttCertWithExtAttCertListWithSessID'
        aaURI = self.cfg.get(section, 'aaURI')
        
        # Use output from test6GetAttCertWithSessID!
        extACFilePath = xpdVars(self.cfg.get(section, 'extACFilePath'))   
        extAttCert = open(extACFilePath).read()
        
        attCert = self.sm.getAttCert(sessID=self.sessID, 
                                     attributeAuthorityURI=aaURI,
                                     extAttCertList=[extAttCert])
        print("Attribute Certificate:\n%s" % attCert)  


    def test11GetAttCertWithUserX509Cert(self):
        """test11GetAttCertWithUserX509Cert: make an attribute request using
        a user cert as authentication credential"""
        self._connect2UserX509CertAuthNService()

        # Request an attribute certificate from an Attribute Authority 
        # using the userX509Cert returned from connect()
        
        aaURI = self.cfg.get('test11GetAttCertWithUserX509Cert', 'aaURI')
        attCert = self.sm.getAttCert(userX509Cert=self.userX509Cert, 
                                     attributeAuthorityURI=aaURI)
        print("Attribute Certificate:\n%s" % attCert)  


    def test12GetAttCertFromLocalAAInstance(self):
        """test12GetAttCertFromLocalAAInstance: make an attribute request to a
        locally instantiated Attribute Authority"""

        self._connect()
        
        section = 'test12GetAttCertFromLocalAAInstance'
        aaPropFilePath = self.cfg.get(section, 'aaPropFilePath')
        attributeAuthority=AttributeAuthority(propFilePath=aaPropFilePath)
        
        attCert = self.sm.getAttCert(sessID=self.sessID, 
                                     attributeAuthority=attributeAuthority)            
        print("Attribute Certificate:\n%s" % attCert) 
        attCert.filePath = xpdVars(self.cfg.get(section, 'acOutputFilePath')) 
        attCert.write()


class SessionManagerTestSuite(unittest.TestSuite):
    
    def __init__(self):
        print "SessionManagerTestSuite ..."
        smTestCaseMap = map(SessionManagerTestCase,
                          (
                            "test01Connect2AuthNServiceWithNoUserX509CertReturned",
                            "test02Connect2AuthNServiceReturningAUserX509Cert",
                            "test03GetSessionStatus",
                            "test04ConnectNoCreateServerSess",
                            "test05DisconnectWithSessID",
                            "test06DisconnectWithUserX509Cert",
                            "test07GetAttCertWithSessID",
                            "test08GetAttCertRefusedWithSessID",
                            "test09GetMappedAttCertWithSessID",
                            "test10GetAttCertWithExtAttCertListWithSessID",
                            "test11GetAttCertWithUserX509Cert",
                            "test12GetAttCertFromLocalAAInstance",
                          ))
        unittest.TestSuite.__init__(self, smTestCaseMap)
            
                                                    
if __name__ == "__main__":
#    suite = SessionManagerTestSuite()
#    unittest.TextTestRunner(verbosity=2).run(suite)
    unittest.main()        
