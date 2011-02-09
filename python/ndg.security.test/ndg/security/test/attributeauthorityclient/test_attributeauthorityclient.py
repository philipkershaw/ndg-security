#!/usr/bin/env python
"""NDG Attribute Authority SOAP client unit tests

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "05/05/05, major update 16/01/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:test_attributeauthorityclient.py 4372 2008-10-29 09:45:39Z pjkersha $'

import unittest
import os, sys, getpass, re
import logging
logging.basicConfig()

from ndg.security.test import BaseTestCase

from ndg.security.common.attributeauthority import AttributeAuthorityClient, \
    NoMatchingRoleInTrustedHosts
from ndg.security.common.AttCert import AttCertRead
from ndg.security.common.X509 import X509CertParse, X509CertRead
from ndg.security.common.utils.configfileparsers import \
    CaseSensitiveConfigParser
    
from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_AACLNT_UNITTEST_DIR'], file)


class AttributeAuthorityClientTestCase(BaseTestCase):
    clntPriKeyPwd = None
    pemPat = "-----BEGIN CERTIFICATE-----[^\-]*-----END CERTIFICATE-----"

    def _getCertChainFromProxyCertFile(self, proxyCertFilePath):
        '''Read proxy cert and user cert from a single PEM file and put in
        a list ready for input into SignatureHandler'''               
        proxyCertFileTxt = open(proxyCertFilePath).read()
        
        pemPatRE = re.compile(self.__class__.pemPat, re.S)
        x509CertList = pemPatRE.findall(proxyCertFileTxt)
        
        signingCertChain = [X509CertParse(x509Cert) for x509Cert in \
                            x509CertList]
    
        # Expecting proxy cert first - move this to the end.  This will
        # be the cert used to verify the message signature
        signingCertChain.reverse()
        
        return signingCertChain


    def setUp(self):
        super(AttributeAuthorityClientTestCase, self).setUp()
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_AACLNT_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_AACLNT_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))

        self.cfgParser = CaseSensitiveConfigParser()
        cfgFilePath = jnPath(os.environ['NDGSEC_AACLNT_UNITTEST_DIR'],
                             'attAuthorityClientTest.cfg')
        self.cfgParser.read(cfgFilePath)
        
        self.cfg = {}
        for section in self.cfgParser.sections():
            self.cfg[section] = dict(self.cfgParser.items(section))

        try:
            sslCACertList = [X509CertRead(xpdVars(file)) for file in \
                         self.cfg['setUp']['sslcaCertFilePathList'].split()]
        except KeyError:
            sslCACertList = []
            
        thisSection = self.cfg['setUp']
        
        # Instantiate WS proxy
        self.siteAClnt = AttributeAuthorityClient(uri=thisSection['uri'],
                                sslPeerCertCN=thisSection.get('sslPeerCertCN'),
                                sslCACertList=sslCACertList,
                                cfgFileSection='wsse',
                                cfg=self.cfgParser)            

    def test01GetHostInfo(self):
        """test01GetHostInfo: retrieve info for AA host"""
        hostInfo = self.siteAClnt.getHostInfo()
        print "Host Info:\n %s" % hostInfo        

    def test02GetTrustedHostInfo(self):
        """test02GetTrustedHostInfo: retrieve trusted host info matching a
        given role"""
        trustedHostInfo = self.siteAClnt.getTrustedHostInfo(\
                                 self.cfg['test02GetTrustedHostInfo']['role'])
        for hostname, hostInfo in trustedHostInfo.items():
            self.assert_(hostname, "Hostname not set")
            for k, v in hostInfo.items():
                self.assert_(k, "hostInfo value key unset")

        print "Trusted Host Info:\n %s" % trustedHostInfo

    def test03GetTrustedHostInfoWithNoMatchingRoleFound(self):
        """test03GetTrustedHostInfoWithNoMatchingRoleFound: test the case 
        where the input role doesn't match any roles in the target AA's map 
        config file"""
        _cfg = self.cfg['test03GetTrustedHostInfoWithNoMatchingRoleFound']
        try:
            trustedHostInfo = self.siteAClnt.getTrustedHostInfo(_cfg['role'])
            self.fail("Expecting NoMatchingRoleInTrustedHosts exception")
            
        except NoMatchingRoleInTrustedHosts, e:
            print 'As expected - no match for role "%s": %s' % \
                (_cfg['role'], e)


    def test04GetTrustedHostInfoWithNoRole(self):
        """test04GetTrustedHostInfoWithNoRole: retrieve trusted host info 
        irrespective of role"""
        trustedHostInfo = self.siteAClnt.getTrustedHostInfo()
        for hostname, hostInfo in trustedHostInfo.items():
            self.assert_(hostname, "Hostname not set")
            for k, v in hostInfo.items():
                self.assert_(k, "hostInfo value key unset")
                   
        print "Trusted Host Info:\n %s" % trustedHostInfo
        

    def test05GetAllHostsInfo(self):
        """test05GetAllHostsInfo: retrieve info for all hosts"""
        allHostInfo = self.siteAClnt.getAllHostsInfo()
        for hostname, hostInfo in allHostInfo.items():
            self.assert_(hostname, "Hostname not set")
            for k, v in hostInfo.items():
                self.assert_(k, "hostInfo value key unset")
                   
        print "All Hosts Info:\n %s" % allHostInfo


    def test06GetAttCert(self):        
        """test06GetAttCert: Request attribute certificate from NDG Attribute 
        Authority Web Service."""
        _cfg = self.cfg['test06GetAttCert']
        
        # Read user Certificate into a string ready for passing via WS
        try:
            userX509CertFilePath = xpdVars(_cfg.get('issuingClntCertFilePath'))
            userX509CertTxt = open(userX509CertFilePath, 'r').read()
        
        except TypeError:
            # No issuing cert set
            userX509CertTxt = None
                
        except IOError, ioErr:
            raise Exception("Error reading certificate file \"%s\": %s" % \
                                    (ioErr.filename, ioErr.strerror))

        # Make attribute certificate request
        attCert = self.siteAClnt.getAttCert(userX509Cert=userX509CertTxt)
        
        print "Attribute Certificate: \n\n:" + str(attCert)
        
        attCert.filePath = xpdVars(_cfg['attCertFilePath'])
        attCert.write()
        
        
    def test07GetAttCertWithUserIdSet(self):        
        """test07GetAttCertWithUserIdSet: Request attribute certificate from 
        NDG Attribute Authority Web Service setting a specific user Id 
        independent of the signer of the SOAP request."""
        _cfg = self.cfg['test07GetAttCertWithUserIdSet']
        
        # Read user Certificate into a string ready for passing via WS
        try:
            userX509CertFilePath = xpdVars(_cfg.get('issuingClntCertFilePath'))
            userX509CertTxt = open(userX509CertFilePath, 'r').read()
        
        except TypeError:
            # No issuing cert set
            userX509CertTxt = None
                
        except IOError, ioErr:
            raise Exception("Error reading certificate file \"%s\": %s" % \
                                    (ioErr.filename, ioErr.strerror))

        # Make attribute certificate request
        userId = _cfg['userId']
        attCert = self.siteAClnt.getAttCert(userId=userId,
                                            userX509Cert=userX509CertTxt)
        
        print "Attribute Certificate: \n\n:" + str(attCert)
        
        attCert.filePath = xpdVars(_cfg['attCertFilePath'])
        attCert.write()


    def test08GetMappedAttCert(self):        
        """test08GetMappedAttCert: Request mapped attribute certificate from 
        NDG Attribute Authority Web Service."""
        _cfg = self.cfg['test08GetMappedAttCert']
        
        # Read user Certificate into a string ready for passing via WS
        try:
            userX509CertFilePath = xpdVars(_cfg.get('issuingClntCertFilePath'))
            userX509CertTxt = open(userX509CertFilePath, 'r').read()
        
        except TypeError:
            # No issuing cert set
            userX509CertTxt = None
                
        except IOError, ioErr:
            raise Exception("Error reading certificate file \"%s\": %s" % \
                                    (ioErr.filename, ioErr.strerror))
    
        # Simlarly for Attribute Certificate 
        try:
            userAttCert = AttCertRead(xpdVars(_cfg['userAttCertFilePath']))
            
        except IOError, ioErr:
            raise Exception("Error reading attribute certificate file \"%s\": "
                            "%s" % (ioErr.filename, ioErr.strerror))
        
        # Make client to site B Attribute Authority
        siteBClnt = AttributeAuthorityClient(uri=_cfg['uri'], 
                                       cfgFileSection='wsse',
                                       cfg=self.cfgParser)
    
        # Make attribute certificate request
        attCert = siteBClnt.getAttCert(userX509Cert=userX509CertTxt,
                                       userAttCert=userAttCert)
        print "Attribute Certificate: \n\n:" + str(attCert)
        
        attCert.filePath = xpdVars(_cfg['mappedAttCertFilePath'])
        attCert.write()
        
        
    def test09GetMappedAttCertStressTest(self):        
        """test09GetMappedAttCertStressTest: Request mapped attribute 
        certificate from NDG Attribute Authority Web Service."""
        _cfg = self.cfg['test09GetMappedAttCertStressTest']
        
        # Read user Certificate into a string ready for passing via WS
        try:
            userX509CertFilePath = xpdVars(_cfg.get('issuingClntCertFilePath'))
            userX509CertTxt = open(userX509CertFilePath, 'r').read()
        
        except TypeError:
            # No issuing cert set
            userX509CertTxt = None
                
        except IOError, ioErr:
            raise Exception("Error reading certificate file \"%s\": %s" % 
                                    (ioErr.filename, ioErr.strerror))

        # Make client to site B Attribute Authority
        siteBClnt = AttributeAuthorityClient(uri=_cfg['uri'], 
                                       cfgFileSection='wsse',
                                       cfg=self.cfgParser)

        acFilePathList = [xpdVars(file) for file in \
                          _cfg['userAttCertFilePathList'].split()]

        for acFilePath in acFilePathList:
            try:
                userAttCert = AttCertRead(acFilePath)
                
            except IOError, ioErr:
                raise Exception("Error reading attribute certificate file "
                                '"%s": %s' % (ioErr.filename, ioErr.strerror))
        
            # Make attribute certificate request
            try:
                attCert = siteBClnt.getAttCert(userX509Cert=userX509CertTxt,
                                               userAttCert=userAttCert)
            except Exception, e:
                outFilePfx = 'test09GetMappedAttCertStressTest-%s' % \
                        os.path.basename(acFilePath)    
                msgFile = open(outFilePfx+".msg", 'w')
                msgFile.write('Failed for "%s": %s\n' % (acFilePath, e))
             
             
class AttributeAuthorityClientTestSuite(unittest.TestSuite):
    def __init__(self):
        map = map(AttributeAuthorityClientTestCase,
                  (
                    "test01GetHostInfo",
                    "test02GetTrustedHostInfo",
                    "test03GetTrustedHostInfoWithNoMatchingRoleFound",
                    "test04GetTrustedHostInfoWithNoRole",
                    "test05GetAllHostsInfo",
                    "test06GetAttCert",
                    "test07GetAttCertWithUserIdSet",
                    "test08GetMappedAttCert",
                    "test09GetMappedAttCertStressTest",
                  ))
        unittest.TestSuite.__init__(self, map)
                                        
if __name__ == "__main__":
    unittest.main()
