#!/usr/bin/env python
"""Test harness for NDG Session Manager - makes requests for 
authentication and authorisation.  An Attribute Authority and Simple CA
services must be running for the reqAuthorisation and addUser tests

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/11/07"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

import unittest
import os, sys, getpass, re
from ConfigParser import SafeConfigParser
import traceback

from ndg.security.common.X509 import X509CertParse
from ndg.security.server.SessionMgr import *
from ndg.security.server.MyProxy import MyProxyClient

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_SM_UNITTEST_DIR'], file)


class SessionMgrTestCase(unittest.TestCase):
    """Unit test case for ndg.security.server.SessionMgr.SessionMgr class.
    
    This class manages server side sessions"""
    
    test1Passphrase = None
    test3Passphrase = None
    
    def setUp(self):
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_SM_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_SM_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))
        
        self.cfg = SafeConfigParser()
        configFilePath = jnPath(os.environ['NDGSEC_SM_UNITTEST_DIR'],
                                "sessionMgrTest.cfg")
        self.cfg.read(configFilePath)
                    
        # Initialise the Session Manager client connection
        # Omit traceFile keyword to leave out SOAP debug info
        propFilePath = xpdVars(self.cfg.get('setUp', 'propFilePath'))
        self.sm = SessionMgr(propFilePath=propFilePath)
        
                                  
    def test1Connect(self):
        """test1Connect: make a new session"""
        
        print "\n\t" + self.test1Connect.__doc__
        
        username = self.cfg.get('test1Connect', 'username')
        
        if SessionMgrTestCase.test1Passphrase is None and \
           self.cfg.has_option('test1Connect', 'passphrase'):
            SessionMgrTestCase.test1Passphrase = \
                                    self.cfg.get('test1Connect', 'passphrase')
        
        if not SessionMgrTestCase.test1Passphrase:
            SessionMgrTestCase.test1Passphrase = getpass.getpass(\
                prompt="\ntest1Connect pass-phrase for user %s: " % username)

        userCert, self.userPriKey, self.issuingCert, self.sessID = \
            self.sm.connect(username=username, 
                            passphrase=SessionMgrTestCase.test1Passphrase)
        self.userCert = X509CertParse(userCert)
        
        print "User '%s' connected to Session Manager:\n%s" % \
                                                        (username, self.sessID)
        creds='\n'.join((self.issuingCert or '',self.userCert,self.userPriKey))
        open(mkPath("user.creds"), "w").write(creds)
    
            
    def test2GetSessionStatus(self):
        """test2GetSessionStatus: check a session is alive"""
        print "\n\t" + self.test2GetSessionStatus.__doc__
        
        self.test1Connect()
        assert self.sm.getSessionStatus(sessID=self.sessID), "Session is dead"
        print "User connected to Session Manager with sessID=%s" % self.sessID

        assert not self.sm.getSessionStatus(sessID='abc'), \
            "sessID=abc shouldn't exist!"
            
        print "CORRECT: sessID=abc doesn't exist"
        
    def test3ConnectNoCreateServerSess(self):
        """test3ConnectNoCreateServerSess: Connect as a non browser client - 
        sessID should be None"""

        print "\n\t" + self.test3ConnectNoCreateServerSess.__doc__
        
        username = self.cfg.get('test3ConnectNoCreateServerSess', 'username')

        if SessionMgrTestCase.test3Passphrase is None and \
           self.cfg.has_option('test3ConnectNoCreateServerSess', 
                               'passphrase'):
            SessionMgrTestCase.test3Passphrase = \
                self.cfg.get('test3ConnectNoCreateServerSess', 'passphrase')
        
        if not SessionMgrTestCase.test3Passphrase:
            SessionMgrTestCase.test3Passphrase = getpass.getpass(\
        prompt="\ntest3ConnectNoCreateServerSess pass-phrase for user %s: " % \
            username)

        self.userCert, self.userPriKey, self.issuingCert, sessID = \
            self.sm.connect(username=username, 
                            passphrase=SessionMgrTestCase.test3Passphrase,
                            createServerSess=False)
        
        # Expect null session ID
        assert not sessID, "Expecting a null session ID!"
          
        print "User '%s' retrieved creds. from Session Manager:\n%s" % \
                                                    (username, self.userCert)
            

    def test4DisconnectWithSessID(self):
        """test4DisconnectWithSessID: disconnect as if acting as a browser client 
        """
        
        print "\n\t" + self.test4DisconnectWithSessID.__doc__
        self.test1Connect()        
        self.sm.deleteUserSession(sessID=self.sessID)
        
        print "User disconnected from Session Manager:\n%s" % self.sessID
            

    def test5DisconnectWithUserCert(self):
        """test5DisconnectWithUserCert: Disconnect as a command line client 
        """
        
        print "\n\t" + self.test5DisconnectWithUserCert.__doc__
        self.test1Connect()
        
        # Proxy cert in signature determines ID of session to
        # delete
        self.sm.deleteUserSession(userCert=self.userCert)
        print "User disconnected from Session Manager:\n%s" % self.userCert


    def test6GetAttCertWithSessID(self):
        """test6GetAttCertWithSessID: make an attribute request using
        a session ID as authentication credential"""

        print "\n\t" + self.test6GetAttCertWithSessID.__doc__        
        self.test1Connect()
        
        attCert, errMsg, extAttCertList = self.sm.getAttCert(\
            sessID=self.sessID, 
            aaURI=self.cfg.get('test6GetAttCertWithSessID', 'aauri'))
        if errMsg:
            self.fail(errMsg)
            
        print "Attribute Certificate:\n%s" % attCert 
        attCert.filePath = \
            xpdVars(self.cfg.get('test6GetAttCertWithSessID', 'acoutfilepath')) 
        attCert.write()
        
        return self.sm


    def test6aGetAttCertRefusedWithSessID(self):
        """test6aGetAttCertRefusedWithSessID: make an attribute request using
        a sessID as authentication credential requesting an AC from an
        Attribute Authority where the user is NOT registered"""

        print "\n\t" + self.test6aGetAttCertRefusedWithSessID.__doc__        
        self.test1Connect()
        
        aaURI = self.cfg.get('test6aGetAttCertRefusedWithSessID', 'aauri')
        
        attCert, errMsg, extAttCertList = self.sm.getAttCert(sessID=self.sessID, 
                                         aaURI=aaURI,
                                         mapFromTrustedHosts=False)
        if errMsg:
            print "SUCCESS - obtained expected result: %s" % errMsg
            return
        
        self.fail("Request allowed from AA where user is NOT registered!")


    def test6bGetMappedAttCertWithSessID(self):
        """test6bGetMappedAttCertWithSessID: make an attribute request using
        a session ID as authentication credential"""

        print "\n\t" + self.test6bGetMappedAttCertWithSessID.__doc__        
        self.test1Connect()
        
        # Attribute Certificate cached in test 6 can be used to get a mapped
        # AC for this test ...
        self.sm = self.test6GetAttCertWithSessID()

        aaURI = self.cfg.get('test6bGetMappedAttCertWithSessID', 'aauri')
        
        attCert, errMsg, extAttCertList=self.sm.getAttCert(sessID=self.sessID,
                                                   aaURI=aaURI,
                                                   mapFromTrustedHosts=True)
        if errMsg:
            self.fail(errMsg)
            
        print "Attribute Certificate:\n%s" % attCert  


    def test6cGetAttCertWithExtAttCertListWithSessID(self):
        """test6cGetAttCertWithSessID: make an attribute request using
        a session ID as authentication credential"""
        
        print "\n\t" + \
            self.test6cGetAttCertWithExtAttCertListWithSessID.__doc__        
        self.test1Connect()
        
        aaURI = \
            self.cfg.get('test6cGetAttCertWithExtAttCertListWithSessID', 'aauri')
        
        # Use output from test6GetAttCertWithSessID!
        extACFilePath = \
        xpdVars(self.cfg.get('test6cGetAttCertWithExtAttCertListWithSessID', 
                             'extacfilepath'))   
        extAttCert = open(extACFilePath).read()
        
        attCert, errMsg, extAttCertList = self.sm.getAttCert(
                                                   sessID=self.sessID, 
                                                   aaURI=aaURI,
                                                   extAttCertList=[extAttCert])
        if errMsg:
            self.fail(errMsg)
          
        print "Attribute Certificate:\n%s" % attCert  


    def test7GetAttCertWithUserCert(self):
        """test7GetAttCertWithUserCert: make an attribute request using
        a user cert as authentication credential"""
        print "\n\t" + self.test7GetAttCertWithUserCert.__doc__
        self.test1Connect()

        # Request an attribute certificate from an Attribute Authority 
        # using the userCert returned from connect()
        
        aaURI = self.cfg.get('test7GetAttCertWithUserCert', 'aauri')
        attCert, errMsg, extAttCertList = self.sm.getAttCert(\
                                     userCert=self.userCert, aaURI=aaURI)
        if errMsg:
            self.fail(errMsg)
          
        print "Attribute Certificate:\n%s" % attCert  


#_____________________________________________________________________________       
class SessionMgrTestSuite(unittest.TestSuite):
    
    def __init__(self):
        print "SessionMgrTestSuite ..."
        smTestCaseMap = map(SessionMgrTestCase,
                          (
                            "test1Connect",
                            "test2GetSessionStatus",
                            "test3ConnectNoCreateServerSess",
                            "test4DisconnectWithSessID",
                            "test5DisconnectWithUserCert",
                            "test6GetAttCertWithSessID",
                            "test6bGetMappedAttCertWithSessID",
                            "test6cGetAttCertWithExtAttCertListWithSessID",
                            "test7GetAttCertWithUserCert",
                          ))
        unittest.TestSuite.__init__(self, smTestCaseMap)
            
                                                    
if __name__ == "__main__":
#    suite = SessionMgrTestSuite()
#    unittest.TextTestRunner(verbosity=2).run(suite)
    unittest.main()        
