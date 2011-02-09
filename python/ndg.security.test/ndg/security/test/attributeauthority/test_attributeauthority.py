#!/usr/bin/env python
"""NDG Attribute Authority

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/12/08"
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
import re
import logging
logging.basicConfig()

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file:jnPath(os.environ['NDGSEC_AA_UNITTEST_DIR'], file)

from ndg.security.test import BaseTestCase

from ndg.security.common.utils.configfileparsers import \
    CaseSensitiveConfigParser
from ndg.security.server.attributeauthority import AttributeAuthority, \
    AttributeAuthorityNoMatchingRoleInTrustedHosts

from ndg.security.common.AttCert import AttCert


class AttributeAuthorityTestCase(BaseTestCase):
    clntPriKeyPwd = None

    def setUp(self):
        super(AttributeAuthorityTestCase, self).setUp()
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_AA_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_AA_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))

        self.cfgParser = CaseSensitiveConfigParser()
        cfgFilePath = mkPath('test_attributeauthority.cfg')
        self.cfgParser.read(cfgFilePath)
        
        self.cfg = {}
        for section in self.cfgParser.sections() + ['DEFAULT']:
            self.cfg[section] = dict(self.cfgParser.items(section))
            
        self.aa = AttributeAuthority(
                                propFilePath=self.cfg['setUp']['propFilePath'])            

    _mkSiteBAttributeAuthority = lambda self: AttributeAuthority(\
                        propFilePath=self.cfg['DEFAULT']['siteBPropFilePath'])
    
    def test01GetHostInfo(self):
        """test01GetHostInfo: retrieve info for AA host"""
        hostInfo = self.aa.hostInfo
        print("Host Info:\n %s" % hostInfo)     

    def test02GetTrustedHostInfo(self):
        """test02GetTrustedHostInfo: retrieve trusted host info matching a
        given role"""
        thisSection = self.cfg['test02GetTrustedHostInfo']
        
        trustedHostInfo = self.aa.getTrustedHostInfo(thisSection['role'])
        for hostname, hostInfo in trustedHostInfo.items():
            self.assert_(hostname, "Hostname not set")
            for k, v in hostInfo.items():
                self.assert_(k, "hostInfo value key unset")

        print("Trusted Host Info:\n %s" % trustedHostInfo)

    def test03GetTrustedHostInfoWithNoMatchingRoleFound(self):
        """test03GetTrustedHostInfoWithNoMatchingRoleFound: test the case 
        where the input role doesn't match any roles in the target AA's map 
        config file"""
        thisSection=self.cfg['test03GetTrustedHostInfoWithNoMatchingRoleFound']
        try:
            trustedHostInfo = self.aa.getTrustedHostInfo(thisSection['role'])
            self.fail("Expecting NoMatchingRoleInTrustedHosts exception")
            
        except AttributeAuthorityNoMatchingRoleInTrustedHosts, e:
            print('PASSED - no match for role "%s": %s' % (thisSection['role'],
                                                           e))


    def test04GetTrustedHostInfoWithNoRole(self):
        """test04GetTrustedHostInfoWithNoRole: retrieve trusted host info 
        irrespective of role"""
        trustedHostInfo = self.aa.getTrustedHostInfo()
        for hostname, hostInfo in trustedHostInfo.items():
            self.assert_(hostname, "Hostname not set")
            for k, v in hostInfo.items():
                self.assert_(k, "hostInfo value key unset")
                   
        print("Trusted Host Info:\n %s" % trustedHostInfo)

    def test05GetAttCert(self):        
        """test05GetAttCert: Request attribute certificate from NDG Attribute 
        Authority Web Service."""
        thisSection = self.cfg['test05GetAttCert']
        
        # Read user Certificate into a string ready for passing via WS
        try:
            userX509CertFilePath = xpdVars(thisSection.get(
                                                    'issuingClntCertFilePath'))
            userX509CertTxt = open(userX509CertFilePath, 'r').read()
        
        except TypeError:
            # No issuing cert set
            userX509CertTxt = None
                
        except IOError, ioErr:
            raise Exception("Error reading certificate file \"%s\": %s" %
                                    (ioErr.filename, ioErr.strerror))

        # Make attribute certificate request
        attCert = self.aa.getAttCert(holderX509Cert=userX509CertTxt)
        
        print("Attribute Certificate: \n\n:" + str(attCert))
        
        attCert.filePath = xpdVars(thisSection['attCertFilePath'])
        attCert.write()
        
        
    def test06GetAttCertWithUserIdSet(self):        
        """test06GetAttCertWithUserIdSet: Request attribute certificate from 
        NDG Attribute Authority Web Service setting a specific user Id 
        independent of the signer of the SOAP request."""
        thisSection = self.cfg['test06GetAttCertWithUserIdSet']
        
        # Make attribute certificate request
        userId = thisSection['userId']
        attCert = self.aa.getAttCert(userId=userId)
        
        print("Attribute Certificate: \n\n:" + str(attCert))
        
        attCert.filePath = xpdVars(thisSection['attCertFilePath'])
        attCert.write()


    def test07GetMappedAttCert(self):        
        """test07GetMappedAttCert: Request mapped attribute certificate from 
        NDG Attribute Authority Web Service."""
        thisSection = self.cfg['test07GetMappedAttCert']
        
        # Read user Certificate into a string ready for passing via WS
        try:
            userX509CertFilePath = xpdVars(thisSection.get(
                                                    'issuingClntCertFilePath'))
            userX509CertTxt = open(userX509CertFilePath, 'r').read()
        
        except TypeError:
            # No issuing cert set
            userX509CertTxt = None
                
        except IOError, ioErr:
            raise Exception("Error reading certificate file \"%s\": %s" % 
                                    (ioErr.filename, ioErr.strerror))
    
        # Simlarly for Attribute Certificate 
        try:
            userAttCert = AttCert.Read(
                                xpdVars(thisSection['userAttCertFilePath']))
            
        except IOError, ioErr:
            raise Exception("Error reading attribute certificate file \"%s\": "
                            "%s" % (ioErr.filename, ioErr.strerror))
        
        # Make client to site B Attribute Authority
        siteBAA = self._mkSiteBAttributeAuthority()
    
        # Make attribute certificate request
        attCert = siteBAA.getAttCert(holderX509Cert=userX509CertTxt,
                                     userAttCert=userAttCert)
        print("Attribute Certificate: \n\n:" + str(attCert))
        
        attCert.filePath = xpdVars(thisSection['mappedAttCertFilePath'])
        attCert.write()
        
        
    def test08GetMappedAttCertStressTest(self):        
        """test08GetMappedAttCertStressTest: Request mapped attribute 
        certificate from NDG Attribute Authority Web Service."""
        thisSection = self.cfg['test08GetMappedAttCertStressTest']
        
        # Read user Certificate into a string ready for passing via WS
        try:
            userX509CertFilePath = xpdVars(thisSection.get(
                                                    'issuingClntCertFilePath'))
            userX509CertTxt = open(userX509CertFilePath, 'r').read()
        
        except TypeError:
            # No issuing cert set
            userX509CertTxt = None
                
        except IOError, ioErr:
            raise Exception("Error reading certificate file \"%s\": %s" % 
                                    (ioErr.filename, ioErr.strerror))

        # Make client to site B Attribute Authority
        siteBAA = self._mkSiteBAttributeAuthority()

        acFilePathList = [xpdVars(file) for file in \
                          thisSection['userAttCertFilePathList'].split()]

        passed = True
        for acFilePath in acFilePathList:
            try:
                userAttCert = AttCert.Read(acFilePath)
                
            except IOError, ioErr:
                raise Exception("Error reading attribute certificate file "
                                '"%s": %s' % (ioErr.filename, ioErr.strerror))
        
            # Make attribute certificate request
            try:
                attCert = siteBAA.getAttCert(holderX509Cert=userX509CertTxt,
                                             userAttCert=userAttCert)
            except Exception, e:
                passed = True
                outFilePfx = 'test08GetMappedAttCertStressTest-%s' % \
                        os.path.basename(acFilePath)    
                msgFile = open(outFilePfx+".msg", 'w')
                msgFile.write('Failed for "%s": %s\n' % (acFilePath, e))
                
        self.assert_(passed, 
                     "At least one Attribute Certificate request failed.  "
                     "Check the .msg files in this directory")
                                        
if __name__ == "__main__":
    unittest.main()
