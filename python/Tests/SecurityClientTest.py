#!/usr/bin/env python

"""Test harness for NDG Security client - makes requests for authentication 
and authorisation

NERC Data Grid Project

P J Kershaw 23/02/06

(Renamed from SessionClientTest.py 27/0/4/06)

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
import unittest
import os

from Cookie import SimpleCookie

from NDG.SecurityClient import *


class SecurityClientTestCase(unittest.TestCase):
    
    def setUp(self):
        try:
            # Session Manager WSDL
            self.smWSDL = 'http://glue.badc.rl.ac.uk/sessionMgr.wsdl'
#            self.smWSDL = 'http://gabriel.bnsc.rl.ac.uk/sessionMgr.wsdl'
    
            # Public key of session manager used to encrypt requests
            # If no public key is set, it will be retrieved using the
            # getPubKey WS method
            smPubKeyFilePath = None

            self.__clntPriKeyPwd = open("./tmp2").read().strip()

            clntPubKeyFilePath = "./Junk-cert.pem"
            clntPriKeyFilePath = "./Junk-key.pem"
            traceFile = None#sys.stderr
            
            # Initialise the Session Manager client connection
            # Omit traceFile keyword to leave out SOAP debug info
            self.sessClnt = SessionClient(smWSDL=self.smWSDL,
                                        smPubKeyFilePath=smPubKeyFilePath,
                                        clntPubKeyFilePath=clntPubKeyFilePath,
                                        clntPriKeyFilePath=clntPriKeyFilePath,
                                        traceFile=traceFile) 

            # Attribute Authority client tests
#            self.aaWSDL = '/home/pjkersha/Development/security/python/Tests/attAuthority.wsdl'
            self.aaWSDL = 'http://glue.badc.rl.ac.uk/attAuthority.wsdl'
#            self.aaWSDL = 'http://gabriel.bnsc.rl.ac.uk/attAuthority.wsdl'
            aaPubKeyFilePath = None
            
            self.aaClnt = AttAuthorityClient(aaWSDL=self.aaWSDL,
                                        aaPubKeyFilePath=aaPubKeyFilePath,
                                        clntPubKeyFilePath=clntPubKeyFilePath,
                                        clntPriKeyFilePath=clntPriKeyFilePath,
                                        traceFile=traceFile) 
            self.sessCookie = None
            self.proxyCert = None
            self.newUserName = 'lawrence'
#            self.userName = 'gabriel'
            self.userName = 'lawrence'
#            self.trustedHostRequiredRole = 'acsoe'
            self.trustedHostRequiredRole = 'coapec'
        
        except Exception, e:
            self.fail(str(e))
            
            
    def tearDown(self):
        pass


    def testAddUser(self):
        
        try:
            # Uncomment to add a new user ID to the MyProxy repository
            # Note the pass-phrase is read from the file tmp.  To pass
            # explicitly as a string use the 'pPhrase' keyword instead
            self.sessClnt.addUser(self.newUserName, 
                                  pPhraseFilePath="./tmp",
                                  clntPriKeyPwd=self.__clntPriKeyPwd)
            print "Added user '%s'" % self.newUserName
            
        except Exception, e:
            self.fail(str(e))
        

    def testCookieConnect(self):
        
#        import pdb
#        pdb.set_trace()
        try:
            # Connect as if acting as a browser client - a cookie is returned
            sSessCookie = self.sessClnt.connect(self.userName, 
                                        pPhraseFilePath="./tmp",
                                        clntPriKeyPwd=self.__clntPriKeyPwd)
            self.sessCookie = SimpleCookie(sSessCookie)
            print "User '%s' connected to Session Manager:\n%s" % \
                (self.userName, sSessCookie)

        except Exception, e:
            self.fail(str(e))
            

    def testProxyCertConnect(self):
        
        try:
            # Connect as a command line client - a proxyCert is returned        
            self.proxyCert = self.sessClnt.connect(self.userName, 
                                          pPhraseFilePath="./tmp",
                                          createServerSess=True,
                                          getCookie=False,
                                          clntPriKeyPwd=self.__clntPriKeyPwd)
            print "User '%s' connected to Session Manager:\n%s" % \
                (self.userName, self.proxyCert)

        except Exception, e:
            self.fail(str(e))


    def testCookieReqAuthorisation(self):
        try:
            # Request an attribute certificate from an Attribute Authority 
            # using the cookie returned from connect()
            self.testCookieConnect()
            authResp = self.sessClnt.reqAuthorisation(\
                        sessID=self.sessCookie['NDG-ID1'].value, 
                        aaWSDL=self.aaWSDL,
                        encrSessMgrWSDLuri=self.sessCookie['NDG-ID2'].value,
                        clntPriKeyPwd=self.__clntPriKeyPwd)
                                                                  
            # The authorisation response is returned as an object which 
            # behaves like a python dictionary.  See 
            # NDG.SessionMgrIO.AuthorisationResp
            if 'errMsg' in authResp:
                print "Authorisation failed for user %s" % authResp['errMsg']            
            else:
                print "User authorised"
                
            print authResp

        except Exception, e:
            self.fail(str(e))


    def testProxyCertReqAuthorisation(self):
        try:
            self.testProxyCertConnect()
            
            # Request an attribute certificate from an Attribute Authority 
            # using the proxyCert returned from connect()
            authResp = self.sessClnt.reqAuthorisation(\
                                         proxyCert=self.proxyCert,
                                         aaWSDL=self.aaWSDL,
                                         clntPriKeyPwd=self.__clntPriKeyPwd)
                                                 
            # The authorisation response is returned as an object which 
            # behaves like a python dictionary.  See 
            # NDG.SessionMgrIO.AuthorisationResp
            if 'errMsg' in authResp:
                print "Authorisation failed for user %s" % authResp['errMsg']           
            else:
                print "User authorised"
                
            print authResp

        except Exception, e:
            self.fail(str(e))


    def testGetPubKey(self):
        try:
            # Request an attribute certificate from an Attribute Authority 
            # using the proxyCert returned from connect()
            pubKey = self.sessClnt.getPubKey()
                                                 
            print "Public Key:\n" + pubKey

        except Exception, e:
            self.fail(str(e))
           

    def testAAgetHostInfo(self):
        """Call Attribute Authority getHostInfo"""
        
        try:
            hostInfo = self.aaClnt.getHostInfo(
                                           clntPriKeyPwd=self.__clntPriKeyPwd)
            print hostInfo
            
        except Exception, e:
            self.fail(str(e))
           

    def testAAgetTrustedHostInfo(self):
        """Call Attribute Authority getTrustedHostInfo with a given role
        to match against"""
        
#        import pdb
#        pdb.set_trace()
        try:
            trustedHosts = self.aaClnt.getTrustedHostInfo(
                                       role=self.trustedHostRequiredRole,
                                       clntPriKeyPwd=self.__clntPriKeyPwd)
            print trustedHosts
            
        except Exception, e:
            self.fail(str(e))
           

    def testAAgetTrustedHostInfoWithNoRoleSet(self):
        """Call Attribute Authority getTrustedHostInfo"""
        
        import pdb
        pdb.set_trace()
        try:
            trustedHosts = self.aaClnt.getTrustedHostInfo(
                                       clntPriKeyPwd=self.__clntPriKeyPwd)
            print trustedHosts
            
        except Exception, e:
            self.fail(str(e))
           

    def testAAReqAuthorisation(self):
        """Call Attribute Authority authorisation request"""
        
        import pdb
        pdb.set_trace()
        try:
            # Alternative means of getting proxy cert - from file
            #self.proxyCert = open("./proxy.pem").read().strip()
            self.testProxyCertConnect()
            userAttCert = None
            
            ac = self.aaClnt.reqAuthorisation(
                                       proxyCert=self.proxyCert,
                                       userAttCert=userAttCert,
                                       clntPriKeyPwd=self.__clntPriKeyPwd)
            print ac
            
        except Exception, e:
            self.fail(str(e))
            
            
#_____________________________________________________________________________       
class SecurityClientTestSuite(unittest.TestSuite):
    
    def __init__(self):
        map = map(SecurityClientTestCase,
                  (
                    "testAddUser",
                    "testConnect",
                    "testReqAuthorisation",
                    "testGetPubKey",
                    "testAAgetTrustedHostInfo",
                    "testAAReqAuthorisation",
                  ))
        unittest.TestSuite.__init__(self, map)
            
                                                    
if __name__ == "__main__":
    unittest.main()        
