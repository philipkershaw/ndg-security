#!/usr/bin/env python

"""Test harness for NDG Gatekeeper WS Client

NERC Data Grid Project

P J Kershaw 19/05/06


Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
import unittest
import os
import sys
import glob

from NDG.GatekeeperClient import *
from NDG.AttCert import *
        
        
class GatekeeperClientTestCase(unittest.TestCase):
    
    def setUp(self):
        try:
            self.gkClnt = GatekeeperClient(wsdl='../www/html/gatekeeper.wsdl')#,
                                           #traceFile=sys.stderr)
            
            self.attCertFilePath = glob.glob('ac-*.xml')[0] 
            self.sAttCert = open(self.attCertFilePath).read().strip()
            self.attCert = AttCertParse(self.sAttCert)

        except Exception, e:
            self.fail(str(e))
            
            
    def tearDown(self):
        pass


    def testReadAccess(self):
        
        try:
            print "Role for read access: '%s'" % \
                self.gkClnt.readAccess(attCertFilePath=self.attCertFilePath)
            
        except Exception, e:
            self.fail(str(e))


    def testWriteAccess(self):
        
        try:
            print "Role for write access: '%s'" % \
                self.gkClnt.writeAccess(self.sAttCert)
            
        except Exception, e:
            self.fail(str(e))


    def testExecuteAccess(self):
        
        try:
            print "Role for execute access: '%s'" % \
                self.gkClnt.executeAccess(self.attCert)
            
        except Exception, e:
            self.fail(str(e))

            
#_____________________________________________________________________________       
class GatekeeperClientTestSuite(unittest.TestSuite):
    
    def __init__(self):
        logTestMap = map(GatekeeperClientTestCase,
                  (
                    "testReadAccessForRapid",
                    "testWriteAccessForRapid",
                    "testExecuteAccessForRapid"
                  ))
        unittest.TestSuite.__init__(self, logTestMap)
            
                                                    
if __name__ == "__main__":
    unittest.main()        
