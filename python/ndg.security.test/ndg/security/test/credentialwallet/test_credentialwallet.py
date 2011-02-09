#!/usr/bin/env python
"""Unit tests for Credential Wallet class

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "03/10/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import unittest
import os, sys, getpass, re
import traceback

from ndg.security.test import BaseTestCase

from ndg.security.common.utils.configfileparsers import \
                                                    CaseSensitiveConfigParser
from ndg.security.common.X509 import X509CertParse
from ndg.security.common.credentialwallet import CredentialWallet, \
                                        CredentialWalletAttributeRequestDenied
from ndg.security.server.attributeauthority import AttributeAuthority

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_CREDWALLET_UNITTEST_DIR'],file)

import logging
logging.basicConfig(level=logging.DEBUG)


class CredentialWalletTestCase(BaseTestCase):
    """Unit test case for ndg.security.common.credentialwallet.CredentialWallet
    class.
    """
    
    def setUp(self):
        super(CredentialWalletTestCase, self).setUp()
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_CREDWALLET_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_CREDWALLET_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))
        
        self.cfg = CaseSensitiveConfigParser()
        configFilePath = jnPath(os.environ['NDGSEC_CREDWALLET_UNITTEST_DIR'],
                                "credWalletTest.cfg")
        self.cfg.read(configFilePath)

        self.userX509CertFilePath=self.cfg.get('setUp', 'userX509CertFilePath')
        self.userPriKeyFilePath=self.cfg.get('setUp', 'userPriKeyFilePath')
        

    def test01ReadOnlyClassVariables(self):
        
        try:
            CredentialWallet.accessDenied = 'yes'
            self.fail("accessDenied class variable should be read-only")
        except Exception, e:
            print("PASS - accessDenied class variable is read-only")

        try:
            CredentialWallet.accessGranted = False
            self.fail("accessGranted class variable should be read-only")
        except Exception, e:
            print("PASS - accessGranted class variable is read-only")
            
        assert(not CredentialWallet.accessDenied)
        assert(CredentialWallet.accessGranted)
        
        
    def test02SetAttributes(self):
        
        credWallet = CredentialWallet()
        credWallet.userX509Cert=open(xpdVars(self.userX509CertFilePath)).read()
        print("userX509Cert=%s" % credWallet.userX509Cert)
        credWallet.userId = 'ndg-user'
        print("userId=%s" % credWallet.userId)
        
        try:
            credWallet.blah = 'blah blah'
            self.fail("Attempting to set attribute not in __slots__ class "
                      "variable should fail")
        except AttributeError:
            print("PASS - expected AttributeError when setting attribute "
                  "not in __slots__ class variable")
            
        credWallet.caCertFilePathList=None
        credWallet.attributeAuthorityURI='http://localhost/AttributeAuthority'
            
        credWallet.attributeAuthority = None
        credWallet.credentialRepository = None
        credWallet.mapFromTrustedHosts = False
        credWallet.rtnExtAttCertList = True
        credWallet.attCertRefreshElapse = 7200
     
            
    def test03GetAttCertWithUserId(self):
                    
        credWallet = CredentialWallet(cfg=self.cfg.get('setUp', 'cfgFilePath'))
        attCert = credWallet.getAttCert()
        
        # No user X.509 cert is set so the resulting Attribute Certificate
        # user ID should be the same as that set for the wallet
        assert(attCert.userId == credWallet.userId)
        print("Attribute Certificate:\n%s" % attCert)
        
    def test04GetAttCertWithUserX509Cert(self):
                    
        credWallet = CredentialWallet(cfg=self.cfg.get('setUp', 'cfgFilePath'))
        
        # Set a test individual user certificate to override the client 
        # cert. and private key in WS-Security settings in the config file
        credWallet.userX509Cert=open(xpdVars(self.userX509CertFilePath)).read()
        credWallet.userPriKey=open(xpdVars(self.userPriKeyFilePath)).read()
        attCert = credWallet.getAttCert()
        
        # A user X.509 cert. was set so this cert's DN should be set in the
        # userId field of the resulting Attribute Certificate
        assert(attCert.userId == str(credWallet.userX509Cert.dn))
        print("Attribute Certificate:\n%s" % attCert)
         


    def test05GetAttCertRefusedWithUserX509Cert(self):
        
        # Keyword mapFromTrustedHosts overrides any setting in the config file
        # This flag prevents role mapping from a trusted AA and so in this case
        # forces refusal of the request
        credWallet = CredentialWallet(cfg=self.cfg.get('setUp', 'cfgFilePath'),
                                      mapFromTrustedHosts=False)    
        credWallet.userX509CertFilePath = self.userX509CertFilePath
        credWallet.userPriKeyFilePath = self.userPriKeyFilePath
        
        # Set AA URI AFTER user PKI settings so that these are picked in the
        # implicit call to create a new AA Client when the URI is set
        credWallet.attributeAuthorityURI = self.cfg.get('setUp', 
                                                    'attributeAuthorityURI')
        try:
            attCert = credWallet.getAttCert()
        except CredentialWalletAttributeRequestDenied, e:
            print("SUCCESS - obtained expected result: %s" % e)
            return
        
        self.fail("Request allowed from Attribute Authority where user is NOT "
                  "registered!")

    def test06GetMappedAttCertWithUserId(self):
        
        # Call Site A Attribute Authority where user is registered
        credWallet = CredentialWallet(cfg=self.cfg.get('setUp', 'cfgFilePath'))
        attCert = credWallet.getAttCert()

        # Use Attribute Certificate cached in wallet to get a mapped 
        # Attribute Certificate from Site B's Attribute Authority
        siteBURI = self.cfg.get('setUp', 'attributeAuthorityURI')        
        attCert = credWallet.getAttCert(attributeAuthorityURI=siteBURI)
            
        print("Mapped Attribute Certificate from Site B Attribute "
              "Authority:\n%s" % attCert)
                        
    def test07GetAttCertFromLocalAAInstance(self):
        thisSection = 'test07GetAttCertFromLocalAAInstance'
        aaPropFilePath = self.cfg.get(thisSection,
                                      'attributeAuthorityPropFilePath') 
                  
        credWallet = CredentialWallet(cfg=self.cfg.get('setUp', 'cfgFilePath'))
        credWallet.attributeAuthority = AttributeAuthority(
                                            propFilePath=aaPropFilePath)
        attCert = credWallet.getAttCert()
        
        # No user X.509 cert is set so the resulting Attribute Certificate
        # user ID should be the same as that set for the wallet
        assert(attCert.userId == credWallet.userId)
        print("Attribute Certificate:\n%s" % attCert)  
                                                         
if __name__ == "__main__":
    unittest.main()        
