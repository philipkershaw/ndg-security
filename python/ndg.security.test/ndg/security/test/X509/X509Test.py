#!/usr/bin/env python
"""NDG X509 Module unit tests

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "03/01/07"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

import unittest
import os
import sys
import getpass
import traceback

from ConfigParser import SafeConfigParser
from ndg.security.common.X509 import X509CertRead, X509CertParse, X500DN, \
    X509Stack, X509StackError, SelfSignedCert, CertIssuerNotFound

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_X509_UNITTEST_DIR'], file)

class X509TestCase(unittest.TestCase):
    
    def setUp(self):
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_X509_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_X509_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))
        
        configParser = SafeConfigParser()
        configFilePath = jnPath(os.environ['NDGSEC_X509_UNITTEST_DIR'],
                                "x509Test.cfg")
        configParser.read(configFilePath)
        
        self.cfg = {}
        for section in configParser.sections():
            self.cfg[section] = dict(configParser.items(section))
        
            
    def test1X509CertRead(self):
        'test1X509CertRead: read in a cert from file'
        print self.test1X509CertRead.__doc__
        self.x509Cert = \
            X509CertRead(xpdVars(self.cfg['test1X509CertRead']['certfile']))
        assert(self.x509Cert)

    def test2X509CertAsPEM(self):
        'test2X509CertAsPEM: display as a PEM format string'
        self.test1X509CertRead()
        print self.test2X509CertAsPEM.__doc__
        self.pemString = self.x509Cert.asPEM()
        print self.pemString


    def test3X509CertParse(self):
        'test3X509CertParse: parse from a PEM format string'
        self.test2X509CertAsPEM()
        print self.test3X509CertParse.__doc__
        assert(X509CertParse(self.pemString))


    def test4GetDN(self):
        'test4GetDN: extract distinguished name'
        self.test1X509CertRead()
        print self.test4GetDN.__doc__
        self.dn = self.x509Cert.dn
        print self.dn
        
    def test5DN(self):
        'test5DN: test X.500 Distinguished Name attributes'
        print self.test5DN.__doc__
        self.test4GetDN()
        for item in self.dn.items():
            print "%s=%s" % item
        
    def test6DNCmp(self):
        '''test6DNCmp: test X.500 Distinguished Name comparison
        operators'''
        print self.test6DNCmp.__doc__
        self.test4GetDN()
        testDN = X500DN(dn="/O=a/OU=b/CN=c")

        assert(not(testDN == self.dn))
        assert(testDN != self.dn)
        assert(self.dn == self.dn)
        assert(not(self.dn != self.dn))
            
    def test7X509Stack(self):
        '''test7X509Stack: test X509Stack functionality'''
        print self.test7X509Stack.__doc__
        self.test1X509CertRead()
        stack = X509Stack()
        assert(len(stack)==0)
        assert(stack.push(self.x509Cert))
        assert(len(stack)==1)
        print "stack[0] = %s" % stack[0]
        for i in stack:
            print "stack iterator i = %s" % i
        print "stack.pop() = %s" % stack.pop()
        assert(len(stack)==0)
            
    def test8X509StackVerifyCertChain(self):
        '''test8X509StackVerifyCertChain: testVerifyCertChain method'''
        print self.test8X509StackVerifyCertChain.__doc__
        self.test1X509CertRead()
        proxyCert=X509CertRead(xpdVars(\
                   self.cfg['test8X509StackVerifyCertChain']['proxycertfile']))

        stack1 = X509Stack()
        stack1.push(self.x509Cert)
        
        caCert=X509CertRead(xpdVars(\
                   self.cfg['test8X509StackVerifyCertChain']['cacertfile']))
        caStack = X509Stack()
        caStack.push(caCert)
        
        print "Verification of external cert with external CA stack..."
        stack1.verifyCertChain(x509Cert2Verify=proxyCert, 
                               caX509Stack=caStack)
        
        print "Verification of stack content using CA stack..."
        stack1.push(proxyCert)
        stack1.verifyCertChain(caX509Stack=caStack)
        
        print "Verification of stack alone..."
        stack1.push(caCert)
        stack1.verifyCertChain()
        
        print "Reject self-signed cert. ..."
        stack2 = X509Stack()
        try:
            stack2.verifyCertChain()
            raise Exception, "Empty stack error expected"
        except X509StackError:
            pass

        stack2.push(caCert)
        try:
            stack2.verifyCertChain()
            raise Exception, "Reject of self-signed cert. expected"
        except SelfSignedCert:
            pass
        
        print "Accept self-signed cert. ..."
        stack2.verifyCertChain(rejectSelfSignedCert=False)
        
        assert(stack2.pop())
        print "Test no cert. issuer found ..."
        stack2.push(proxyCert)
        try:
            stack2.verifyCertChain()
            raise Exception, "No cert. issuer error expected"
        except CertIssuerNotFound:
            pass
        
        print "Test no cert. issuer found again with incomplete chain ..."
        stack2.push(self.x509Cert)
        try:
            stack2.verifyCertChain()
            raise Exception, "No cert. issuer error expected"
        except CertIssuerNotFound:
            pass
        

class X509TestSuite(unittest.TestSuite):
    def __init__(self):
        map = map(X509TestCase,
                  (
                    "test1X509CertRead",
                    "test2X509CertAsPEM",
                    "test3X509CertParse",
                    "test4GetDN",
                    "test5DN",
                    "test6DNCmp",
                    "test7X509Stack",
                    "test8X509StackVerifyCertChain"
                  ))
        unittest.TestSuite.__init__(self, map)
 
                                       
if __name__ == "__main__":
    unittest.main()