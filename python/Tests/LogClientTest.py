#!/usr/bin/env python

"""Test harness for NDG logging client - send log messages to WS

NERC Data Grid Project

P J Kershaw 12/05/06


Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
import unittest
import os

from NDG.LogClient import *


class LogClientTestCase(unittest.TestCase):
    
    def setUp(self):
        try:
            # Session Manager WSDL
            wsdl = '../www/html/log.wsdl'
    
            
            # Initialise the client connection
            # Omit traceFile keyword to leave out SOAP debug info
            self.logClnt = LogClient(wsdl=wsdl, 
                 signingPubKeyFilePath="./Junk-cert.pem",
                 signingPriKeyFilePath="./Junk-key.pem",
                 signingPriKeyPwd=open("./tmp2").read().strip(), 
                 traceFile=sys.stderr) 

        except Exception, e:
            self.fail(str(e))
            
            
    def tearDown(self):
        pass


    def test1Debug(self):
        
        msg = \
"Never mind that, my lad. I wish to complain about this parrot what I purchased not half an hour ago from this very boutique."
        
        try:
            self.logClnt.debug(msg)
            
        except Exception, e:
            self.fail(str(e))


    def test2Info(self):
        
        msg = \
"Oh yes, the, uh, the Norwegian Blue...What's,uh...What's wrong with it?"
        
        try:
            self.logClnt.info(msg)
            
        except Exception, e:
            self.fail(str(e))


    def test3Warning(self):
        
        msg = \
"I'll tell you what's wrong with it, my lad. 'E's dead, that's what's wrong with it!"
        
        try:
            self.logClnt.warning(msg)
            
        except Exception, e:
            self.fail(str(e))


    def test4Error(self):
        
        msg = "No, no, 'e's uh,...he's resting."
        
        try:
            self.logClnt.error(msg)
            
        except Exception, e:
            self.fail(str(e))
            
            
#_____________________________________________________________________________       
class LogClientTestSuite(unittest.TestSuite):
    
    def __init__(self):
        logTestMap = map(LogClientTestCase,
                  (
                    "test1Debug",
                    "test2Info",
                    "test3Warning",
                    "test4Error",
                  ))
        unittest.TestSuite.__init__(self, logTestMap)
            
                                                    
if __name__ == "__main__":
    unittest.main()        
