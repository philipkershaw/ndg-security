#!/usr/bin/env python

"""Test harness for NDG Session client - makes requests for authentication and
authorisation

NERC Data Grid Project

P J Kershaw 23/02/06

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
import unittest
import os

from Cookie import SimpleCookie

from NDG.SessionClient import *


class sessionClientTestCase(unittest.TestCase):
    
    def setUp(self):
        try:
            # Session Manager WSDL
            smWSDL = 'http://glue.badc.rl.ac.uk/sessionMgr.wsdl'
            #smWSDL = 'http://gabriel.bnsc.rl.ac.uk/sessionMgr.wsdl'
    
            # Public key of session manager used to encrypt requests
            # If no public key is set, it will be retrieved using the
            # getPubKey WS method
            #smPubKeyFilePath = \
            #    os.path.expandvars("$NDG_DIR/conf/certs/badc-sm-cert.pem")
            smPubKeyFilePath = None

            self.__clntPriKeyPwd = open("./tmp2").read().strip()

            clntPubKeyFilePath = os.path.expandvars("$HOME/Junk-cert.pem")
            clntPriKeyFilePath = os.path.expandvars("$HOME/Junk-key.pem")
            
            # Initialise the Session Manager client connection
            # Omit traceFile keyword to leave out SOAP debug info
            self.sessClnt = SessionClient(smWSDL=smWSDL,
                                 smPubKeyFilePath=smPubKeyFilePath,
                                 clntPubKeyFilePath=clntPubKeyFilePath,
                                 clntPriKeyFilePath=clntPriKeyFilePath,
                                 traceFile=sys.stderr) 
        except Exception, e:
            self.fail(str(e))
            
            
    def tearDown(self):
        pass


    def addUserTest(self):
        
        userName = 'pjkersha'
        
        try:
            # Uncomment to add a new user ID to the MyProxy repository
            # Note the pass-phrase is read from the file tmp.  To pass
            # explicitly as a string use the 'pPhrase' keyword instead
            self.sessClnt.addUser(userName, 
                                  pPhraseFilePath="./tmp",
                                  clntPriKeyPwd=self.__clntPriKeyPwd)
            print "Added user '%s'" % userName
            
        except Exception, e:
            self.fail(str(e))
        

    def cookieConnectTest(self):
        
        userName = 'pjkersha'
        try:
            # Connect as if acting as a browser client - a cookie is returned
            sSessCookie = self.sessClnt.connect(userName, 
                                        pPhraseFilePath="./tmp",
                                        clntPriKeyPwd=self.__clntPriKeyPwd)
            self.sessCookie = SimpleCookie(sSessCookie)
            print "User '%s' connected to Session Manager:\n%s" % \
                (userName, sSessCookie)

        except Exception, e:
            self.fail(str(e))
            

    def proxyCertConnectTest(self):
        
        userName = 'pjkersha'
        
        try:
            # Connect as a command line client - a proxyCert is returned        
            proxyCert = self.sessClnt.connect(userName, 
                                          pPhraseFilePath="./tmp",
                                          createServerSess=True,
                                          getCookie=False,
                                          clntPriKeyPwd=self.__clntPriKeyPwd)
            print "User '%s' connected to Session Manager:\n%s" % \
                (userName, proxyCert)

        except Exception, e:
            self.fail(str(e))


    def cookieReqAuthorisationTest(self):
        try:
            # Request an attribute certificate from an Attribute Authority 
            # using the cookie returned from connect()
            authResp = self.sessClnt.reqAuthorisation(\
                        sessID=self.sessCookie['NDG-ID1'].value, 
                        encrSessMgrWSDLuri=self.sessCookie['NDG-ID2'].value,
                        aaWSDL=aaWSDL,
                        clntPriKeyPwd=self.__clntPriKeyPwd)
                                                                  
            # The authorisation response is returned as an object which 
            # behaves like a python dictionary.  See 
            # NDG.SessionMgrIO.AuthorisationResp
            if 'errMsg' in authResp:
                print "Authorisation failed for user '%s':\n" % userName            
            else:
                print "User '%s' authorised:\n" % userName
                
            print authResp

        except Exception, e:
            self.fail(str(e))


    def proxyCertReqAuthorisationTest(self):
        try:
            # Request an attribute certificate from an Attribute Authority 
            # using the proxyCert returned from connect()
            authResp = self.sessClnt.reqAuthorisation(\
                                         proxyCert=self.proxyCert,
                                         aaWSDL=aaWSDL,
                                         clntPriKeyPwd=self.__clntPriKeyPwd)
                                                 
            # The authorisation response is returned as an object which 
            # behaves like a python dictionary.  See 
            # NDG.SessionMgrIO.AuthorisationResp
            if 'errMsg' in authResp:
                print "Authorisation failed for user '%s':\n" % userName            
            else:
                print "User '%s' authorised:\n" % userName
                
            print authResp

        except Exception, e:
            self.fail(str(e))


    def getPubKeyTest(self):
        try:
            # Request an attribute certificate from an Attribute Authority 
            # using the proxyCert returned from connect()
            import pdb
            pdb.set_trace()
            pubKey = self.sessClnt.getPubKey()
                                                 
            print "Public Key:\n" + pubKey

        except Exception, e:
            self.fail(str(e))
            
 
#_____________________________________________________________________________       
class sessionClientTestSuite(unittest.TestSuite):
    def __init__(self):
        map = map(sessionClientTestCase,
                  (
                    "addUserTest",
                    "connectTest",
                    "reqAuthorisationTest",
                    "getPubKeyTest",
                  ))
        unittest.TestSuite.__init__(self, map)
                                        
if __name__ == "__main__":
    unittest.main()        
