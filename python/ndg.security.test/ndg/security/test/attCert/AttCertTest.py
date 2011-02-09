#!/usr/bin/env python
"""NDG AttCert class unit tests

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "03/01/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import unittest
import os
import sys
import getpass
import traceback

from ConfigParser import SafeConfigParser
from ndg.security.common.AttCert import AttCert
from ndg.security.test import BaseTestCase

xpdVars = os.path.expandvars
jnPath = os.path.join
mkPath = lambda file: jnPath(os.environ['NDGSEC_ATTCERT_UNITTEST_DIR'], file)

class AttCertTestCase(BaseTestCase):
    
    def setUp(self):
        super(AttCertTestCase, self).setUp()
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_ATTCERT_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_ATTCERT_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))

        configParser = SafeConfigParser()
        configFilePath = jnPath(os.environ['NDGSEC_ATTCERT_UNITTEST_DIR'],
                                'attCertTest.cfg')
        configParser.read(configFilePath)
        
        self.cfg = {}
        for section in configParser.sections():
            self.cfg[section] = dict(configParser.items(section))

        self.attCert = AttCert()
            
            
    def test1AttCert4NonZero(self):
        'test1AttCert4NonZero: check if test yields True'
        if not self.attCert:
            self.fail("AttCert instance yields 0")

        
    def test2SetProvenance(self):
        'test2SetProvenance'
        self.attCert['provenance'] = AttCert.origProvenance
        print "test2SetProvenance - set to: %s" % self.attCert['provenance']
        
        
    def test3TryToAlterProvenance(self):
        'test3TryToAlterProvenance'
        try:
            AttCert.origProvenance = 'Another provenance setting'
        except AttributeError, e:
            print \
        "test3TryToAlterProvenance - PASSED - expected exception: \"%s\"" % e
        except:
            self.fail('Original provenance should be read-only')
            
            
    def test4SetValidityTime(self):
        'test4SetValidityTime'
        self.attCert.setValidityTime(lifetime=60*60*8.)
        
        print 'test4SetValidityTime: %s' % self.attCert['validity']

        
    def test5SetDefaultValidityTime(self):
        'test5SetDefaultValidityTime: use default settings'
        self.attCert.setValidityTime()
        
        print 'test5SetDefaultValidityTime: %s' % self.attCert['validity']

 
    def test6AddRoles(self):
        'test6AddRoles: add extra roles'
        self.attCert.addRoles(['government', 'acsoe'])
        self.attCert.addRoles('atsr')
        
        print "test6AddRoles: " + ', '.join(self.attCert.roles)

 
    def test6aSet(self):
        'test6aSet: test __setitem__ and property methods'
        self.attCert.version = "1.0"
        self.attCert['issuer'] = '/O=NDG/OU=BADC/CN=Attribute Authority'
        self.attCert['issuerName'] = 'BADC'
        self.attCert.issuerSerialNumber = 1234
        self.attCert['holder'] = '/O=NDG/OU=BADC/CN=server.cert.ac.uk'
        self.attCert.userId = '/O=NDG/OU=BADC/CN=pjkershaw'
        
        try:
            self.attCert['validity'] = 'invalid'
        except KeyError, e:
            print "test6aSet: PASSED - %s" % e
            
        try:
            self.attCert['attributes'] = 'roleSet'
        except KeyError, e:
            print "test6aSet: PASSED - %s" % e
            
        try:
            self.attCert['attributes']['roleSet'] = ['role1', 'role2']
        except KeyError, e:
            print "test6aSet: PASSED - %s" % e

    def test6bGet(self):
        'test6bGet: test __getitem__ and property methods'
        print "test6bGet ..."
        self.test2SetProvenance()
        self.test4SetValidityTime()
        self.test6AddRoles()
        self.test6aSet()

        print "self.attCert['version'] = %s" % self.attCert['version']
        print "self.attCert.version = %s" % self.attCert.version
        
        print "self.attCert['issuer'] = %s" % self.attCert['issuer']
        print "self.attCert.issuer = %s" % self.attCert.issuer
        print "self.attCert.issuerDN = %s" % self.attCert.issuerDN

        print "self.attCert['issuerName'] = %s" % self.attCert['issuerName']
        print "self.attCert.issuerName = %s" % self.attCert.issuerName
        
        print "self.attCert['issuerSerialNumber'] = %s" % \
                                            self.attCert['issuerSerialNumber']
        print "self.attCert.issuerSerialNumber = %s" % \
                                            self.attCert.issuerSerialNumber
        
        print "self.attCert['holder'] = %s" % self.attCert['holder']
        print "self.attCert.holder = %s" % self.attCert.holder
        print "self.attCert.holderDN = %s" % self.attCert.holderDN

        print "self.attCert['userId'] = %s" % self.attCert['userId']
        print "self.attCert.userId = %s" % self.attCert.userId
        
        print "self.attCert['validity'] = %s" % self.attCert['validity']
        print "self.attCert.validityNotBefore = %s" % \
                                                self.attCert.validityNotBefore
        print "self.attCert.validityNotAfter = %s" % \
                                                self.attCert.validityNotAfter
                                                
        print "self.attCert.getValidityNotBefore(asDatetime=True) = %s" % \
                            self.attCert.getValidityNotBefore(asDatetime=True)
        print "self.attCert.getValidityNotAfter(asDatetime=True) = %s" % \
                            self.attCert.getValidityNotAfter(asDatetime=True)
        
        print "self.attCert['attributes'] = %s" % self.attCert['attributes']
        print "self.attCert['attributes']['roleSet'] %s: " % \
                                        self.attCert['attributes']['roleSet'] 
        print "self.attCert.roleSet = %s" % self.attCert.roleSet
        print "self.attCert.roles = %s" % self.attCert.roles

    def test7CreateXML(self):
        'test7CreateXML: check for correct formatted string'
        self.test2SetProvenance()
        self.test5SetDefaultValidityTime()
        self.test6AddRoles()
        print 'test7CreateXML:\n\n' + self.attCert.createXML()

    
    def test8Parse(self):
        '''test8Parse: parse an XML document'''  
        self.attCert.parse(self.attCert.createXML())
        print 'test8Parse:\n\n' + repr(self.attCert)

    def test9Sign(self): 
        '''test9Sign: sign document'''
        self.test2SetProvenance()
        self.test5SetDefaultValidityTime()
        self.test6AddRoles()
        self.test6aSet()    
        
        self.attCert.filePath = xpdVars(self.cfg['test9Sign']['filepath'])
        self.attCert.certFilePathList = \
            xpdVars(self.cfg['test9Sign']['signingcertfilepath'])
        self.attCert.signingKeyFilePath = \
            xpdVars(self.cfg['test9Sign']['signingprikeyfilepath'])
        
        signingKeyPwd = self.cfg['test9Sign'].get('signingprikeypwd')
        if signingKeyPwd is None:
            try:
                self.attCert.signingKeyPwd = \
                getpass.getpass(prompt="\ntest9Sign private key password: ")
            except KeyboardInterrupt:
                self.fail("test9Sign: Aborting test")
                return
        else:
            self.attCert.signingKeyPwd = signingKeyPwd
            
        self.attCert.applyEnvelopedSignature()
        print 'test9Sign: \n\n%s' % self.attCert
    
    
    def test10Write(self):
        '''test10Write: write document'''
            
        self.test9Sign()
        self.attCert.filePath = xpdVars(self.cfg['test10Write']['filepath'])
        self.attCert.write()
      
        
    def test11Read(self):
        '''test11Read: read document'''
            
        self.attCert.filePath = xpdVars(self.cfg['test11Read']['filepath'])
        self.attCert.read()
        print 'test11Read: \n\n%s' % self.attCert
        

    def test12IsValid(self):
        '''test12IsValid: check signature of XML document'''            
        self.test11Read()
        self.attCert.certFilePathList = [xpdVars(file) for file in \
                    self.cfg['test12IsValid']['certfilepathlist'].split()]
        self.attCert.isValid(raiseExcep=True)
        print 'test12IsValid: passed'
        

    def test13IsValidStressTest(self):
        '''test13IsValidStressTest: check signature of XML document'''            
        self.test2SetProvenance()
        self.test5SetDefaultValidityTime()
        self.test6aSet()    
        
        self.attCert.certFilePathList = [xpdVars(file) for file in \
            self.cfg['test13IsValidStressTest']['certfilepathlist'].split()]
        self.attCert.signingKeyFilePath = \
                        xpdVars(self.cfg['test13IsValidStressTest']['signingprikeyfilepath'])
        
        signingKeyPwd = self.cfg['test13IsValidStressTest'].get('signingprikeypwd')
        if signingKeyPwd is None:
            try:
                self.attCert.signingKeyPwd = getpass.getpass(\
                    prompt="\ntest13IsValidStressTest private key password: ")
            except KeyboardInterrupt:
                self.fail("test13IsValidStressTest: Aborting test")
                return
        else:
            self.attCert.signingKeyPwd = signingKeyPwd
            
        import base64
        for i in range(0, int(self.cfg['test13IsValidStressTest']['nruns'])):
            # Generate a range of random role names to try to trip up the
            # signature validation
            roles = [base64.encodestring(os.urandom(i)).strip() \
                     for role in range(0, i)]
            self.attCert.addRoles(roles)
            
            # Write AC file names by index
            self.attCert.filePath = mkPath("stress-test-ac-%03d.xml" % i)
            
            self.attCert.applyEnvelopedSignature()
            self.attCert.write()

            try:
                self.attCert.isValid(raiseExcep=True)
            except Exception, e:
                msg = "Verification failed for %s: %s" % \
                    (self.attCert.filePath, str(e))
                print msg
                open('%03d.msg' % i, 'w').write(msg)    

    def test14IsValidSignature(self):
        '''test14IsValidSignature: check signature of XML document'''            
        self.attCert.filePath = \
            xpdVars(self.cfg['test14IsValidSignature']['filepath'])
        self.attCert.read()
        
        certFilePathList = [xpdVars(file) for file in \
                self.cfg['test14IsValidSignature']['certfilepathlist'].split()]
        
        self.attCert.certFilePathList = certFilePathList
        self.attCert.verifyEnvelopedSignature()
        
        print 'test14IsValidSignature: \n\n%s' % self.attCert
        
class AttCertTestSuite(unittest.TestSuite):
    def __init__(self):
        map = map(AttCertTestCase,
                  (
                    "test1AttCert4NonZero",
                    "test2SetProvenance",
                    "test3TryToAlterProvenance",
                    "test4SetValidityTime",
                    "test5SetDefaultValidityTime",
                    "test6AddRoles",
                    "test7CreateXML",
                    "test8Parse",
                    "test9Sign",
                    "test10Write",
                    "test11Read",
                    "test12IsValid",
                  ))
        unittest.TestSuite.__init__(self, map)
 
                                       
if __name__ == "__main__":
    unittest.main()