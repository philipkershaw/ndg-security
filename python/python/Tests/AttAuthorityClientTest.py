#!/usr/bin/env python

"""NDG Attribute Authority client - makes requests for authorisation

NERC Data Grid Project

P J Kershaw 05/05/05

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
import unittest
import os
import sys

from ZSI import ServiceProxy

from NDG.AttAuthorityIO import *


class attAuthorityClientTestCase(unittest.TestCase):
    
    def setUp(self):
        try:
            # Session Manager WSDL
            aaWSDL = 'http://glue.badc.rl.ac.uk/attAuthority.wsdl'
    
            # Instantiate WS proxy
            self.aaSrv = ServiceProxy(aaWSDL, 
                                      use_wsdl=True, 
                                      tracefile=sys.stderr)
        except Exception, e:
            self.fail(str(e))
            
            
    def tearDown(self):
        pass
    
    
    def getPubKeyTest(self):
        try:
            # Request an attribute certificate from an Attribute Authority 
            # using the proxyCert returned from connect()
#            import pdb
#            pdb.set_trace()
            pubKeyReq = PubKeyReq()
            resp = self.aaSrv.getPubKey(pubKeyReq=pubKeyReq())
            pubKeyResp = PubKeyResp(xmlTxt=resp['pubKeyResp'])
    
            if 'errMsg' in pubKeyResp and pubKeyResp['errMsg']:
                raise Exception(pubKeyResp['errMsg'])
            
            print "Attribute Authority public key:\n" + pubKeyResp['pubKey']
                         
        except Exception, e:
            self.fail(str(e))


    def getTrustedHostInfoTest(self):
        
        try:
            pass
        except Exception, e:
            self.fail(str(e))


    def reqAuthorisationTest(self):        
        """Request authorisation from NDG Attribute Authority Web Service."""
    
        # Attribute Authority WSDL
        aaWSDL = './attAuthority.wsdl'
        
        # User's proxy certificate
        usrProxyCertFilePath = "./certs/pjkproxy.pem"
    
        # Existing Attribute Certificate held in user's CredentialWallet.  
        # This is available for use with trusted data centres to make new 
        # mapped Attribute Certificates
        usrAttCertFilePath = "./attCert/attCert-pjk-BADC.xml"
    
        # Make Attribute Authority raise an exception
        #usrAttCertFilePath = "attCert-tampered.xml"
    
    
        print "Requesting authorisation for user cert file: \"%s\"" % \
              usrProxyCertFilePath
    
    
        # Read user Proxy Certificate into a string ready for passing via WS
        try:
            usrProxyCertFileTxt = open(usrProxyCertFilePath, 'r').read()
            
        except IOError, ioErr:
            raise "Error reading proxy certificate file \"%s\": %s" % \
                                    (ioErr.filename, ioErr.strerror)
    
    
        # Simlarly for Attribute Certificate if present ...
        if usrAttCertFilePath is not None:
            
            try:
                usrAttCertFileTxt = open(usrAttCertFilePath, 'r').read()
                
            except IOError, ioErr:
                raise "Error reading attribute certificate file \"%s\": %s" % \
                                        (ioErr.filename, ioErr.strerror)
        else:
            usrAttCertFileTxt = None
            
    
        # Make authorsation request
        try:   
            resp = self.aaSrv.reqAuthorisation(\
                                          usrProxyCert=usrProxyCertFileTxt,
                                          usrAttCert=usrAttCertFileTxt)
            if resp['errMsg']:
                raise Exception(resp['errMsg'])
            
            return resp['attCert']
            
        except Exception, e:
            self.fail(str(e))
        
 
#_____________________________________________________________________________       
class attAuthorityClientTestSuite(unittest.TestSuite):
    def __init__(self):
        map = map(attAuthorityClientTestCase,
                  (
                    "getTrustedHostInfoTest",
                    "reqAuthorisationTest",
                    "getPubKeyTest",
                  ))
        unittest.TestSuite.__init__(self, map)
                                        
if __name__ == "__main__":
    unittest.main()
