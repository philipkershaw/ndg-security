#!/usr/bin/env python
"""Unit tests for Credential Wallet classes

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "03/10/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'

import unittest
import os, sys, getpass, re
import traceback

from string import Template
from cStringIO import StringIO
import cPickle as pickle

from elementtree import ElementTree

from time import sleep
from datetime import datetime, timedelta
from saml.utils import SAMLDateTime
from saml.xml.etree import AssertionElementTree

from ndg.security.test.unit import BaseTestCase

from ndg.security.common.utils.configfileparsers import (
                                                    CaseSensitiveConfigParser)
from ndg.security.common.utils.etree import prettyPrint
from ndg.security.common.X509 import X509CertParse
from ndg.security.common.credentialwallet import (NDGCredentialWallet, 
    CredentialWalletAttributeRequestDenied, SAMLCredentialWallet)
from ndg.security.server.attributeauthority import AttributeAuthority

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_CREDWALLET_UNITTEST_DIR'], file)

import logging
logging.basicConfig(level=logging.DEBUG)


class NDGCredentialWalletTestCase(BaseTestCase):
    """Unit test case for 
    ndg.security.common.credentialwallet.NDGCredentialWallet class.
    """
    THIS_DIR = os.path.dirname(__file__)
    PICKLE_FILENAME = 'NDGCredentialWalletPickle.dat'
    PICKLE_FILEPATH = os.path.join(THIS_DIR, PICKLE_FILENAME)

    def __init__(self, *arg, **kw):
        super(NDGCredentialWalletTestCase, self).__init__(*arg, **kw)
        self.startAttributeAuthorities()
    
    def setUp(self):
        super(NDGCredentialWalletTestCase, self).setUp()
        
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
            NDGCredentialWallet.accessDenied = 'yes'
            self.fail("accessDenied class variable should be read-only")
        except Exception, e:
            print("PASS - accessDenied class variable is read-only")

        try:
            NDGCredentialWallet.accessGranted = False
            self.fail("accessGranted class variable should be read-only")
        except Exception, e:
            print("PASS - accessGranted class variable is read-only")
            
        assert(not NDGCredentialWallet.accessDenied)
        assert(NDGCredentialWallet.accessGranted)
        
        
    def test02SetAttributes(self):
        
        credWallet = NDGCredentialWallet()
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
        credWallet._credentialRepository = None
        credWallet.mapFromTrustedHosts = False
        credWallet.rtnExtAttCertList = True
        credWallet.attCertRefreshElapse = 7200
     
            
    def test03GetAttCertWithUserId(self):
                    
        credWallet = NDGCredentialWallet(cfg=self.cfg.get('setUp', 
                                                          'cfgFilePath'))
        attCert = credWallet.getAttCert()
        
        # No user X.509 cert is set so the resulting Attribute Certificate
        # user ID should be the same as that set for the wallet
        assert(attCert.userId == credWallet.userId)
        print("Attribute Certificate:\n%s" % attCert)
        
    def test04GetAttCertWithUserX509Cert(self):
                    
        credWallet = NDGCredentialWallet(cfg=self.cfg.get('setUp', 
                                                          'cfgFilePath'))
        
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
        credWallet = NDGCredentialWallet(cfg=self.cfg.get('setUp', 
                                                          'cfgFilePath'),
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
            print("ok - obtained expected result: %s" % e)
            return
        
        self.fail("Request allowed from Attribute Authority where user is NOT "
                  "registered!")

    def test06GetMappedAttCertWithUserId(self):
        
        # Call Site A Attribute Authority where user is registered
        credWallet = NDGCredentialWallet(cfg=self.cfg.get('setUp', 
                                                          'cfgFilePath'))
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
                  
        credWallet = NDGCredentialWallet(cfg=self.cfg.get('setUp', 
                                                          'cfgFilePath'))
        credWallet.attributeAuthority = AttributeAuthority.fromPropertyFile(
                                            propFilePath=aaPropFilePath)
        attCert = credWallet.getAttCert()
        
        # No user X.509 cert is set so the resulting Attribute Certificate
        # user ID should be the same as that set for the wallet
        assert(attCert.userId == credWallet.userId)

    def test08Pickle(self):
        credWallet = NDGCredentialWallet(cfg=self.cfg.get('setUp', 
                                                          'cfgFilePath'))

        outFile = open(NDGCredentialWalletTestCase.PICKLE_FILEPATH, 'w')
        pickle.dump(credWallet, outFile)
        outFile.close()
        
        inFile = open(NDGCredentialWalletTestCase.PICKLE_FILEPATH)
        unpickledCredWallet = pickle.load(inFile)
        self.assert_(unpickledCredWallet.userId == credWallet.userId)
        

class SAMLCredentialWalletTestCase(BaseTestCase):
    THIS_DIR = os.path.dirname(__file__)
    CONFIG_FILENAME = 'test_samlcredentialwallet.cfg'
    CONFIG_FILEPATH = os.path.join(THIS_DIR, CONFIG_FILENAME)
    PICKLE_FILENAME = 'SAMLCredentialWalletPickle.dat'
    PICKLE_FILEPATH = os.path.join(THIS_DIR, PICKLE_FILENAME)
    
    ASSERTION_STR = (
"""<saml:Assertion ID="192c67d9-f9cd-457a-9242-999e7b943166" IssueInstant="$timeNow" Version="2.0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
   <saml:Issuer Format="urn:esg:issuer">$issuerName</saml:Issuer>
   <saml:Subject>
      <saml:NameID Format="urn:esg:openid">https://esg.prototype.ucar.edu/myopenid/testUser</saml:NameID>
   </saml:Subject>
   <saml:Conditions NotBefore="$timeNow" NotOnOrAfter="$timeExpires" />
   <saml:AttributeStatement>
      <saml:Attribute FriendlyName="FirstName" Name="urn:esg:first:name" NameFormat="http://www.w3.org/2001/XMLSchema#string">
         <saml:AttributeValue xsi:type="xs:string" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="LastName" Name="urn:esg:last:name" NameFormat="http://www.w3.org/2001/XMLSchema#string">
         <saml:AttributeValue xsi:type="xs:string" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">User</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="EmailAddress" Name="urn:esg:first:email:address" NameFormat="http://www.w3.org/2001/XMLSchema#string">
         <saml:AttributeValue xsi:type="xs:string" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">test@sitea.ac.uk</saml:AttributeValue>
      </saml:Attribute>
   </saml:AttributeStatement>
</saml:Assertion>
"""
    )
    
    def __init__(self, *arg, **kw):
        super(SAMLCredentialWalletTestCase, self).__init__(*arg, **kw)
        
    def setUp(self):
        self.assertion = self._createAssertion()
        
    def _createAssertion(self, timeNow=None, validityDuration=60*60*8,
                         issuerName=BaseTestCase.SITEA_SAML_ISSUER_NAME):
        if timeNow is None:
            timeNow = datetime.utcnow()
            
        timeExpires = timeNow + timedelta(seconds=validityDuration)
        assertionStr = Template(
            SAMLCredentialWalletTestCase.ASSERTION_STR).substitute(
                dict(
                 issuerName=issuerName,
                 timeNow=SAMLDateTime.toString(timeNow), 
                 timeExpires=SAMLDateTime.toString(timeExpires)
                )
            )

        assertionStream = StringIO()
        assertionStream.write(assertionStr)
        assertionStream.seek(0)
        assertionElem = ElementTree.parse(assertionStream).getroot()
        return AssertionElementTree.fromXML(assertionElem)

    def _addCredential(self):
        wallet = SAMLCredentialWallet()   
        wallet.addCredential(
            self.assertion, 
            attributeAuthorityURI=\
                SAMLCredentialWalletTestCase.SITEA_ATTRIBUTEAUTHORITY_SAML_URI)
        return wallet
    
    def test01AddCredential(self):
        wallet = self._addCredential()
        
        self.assert_(len(wallet.credentials) == 1)
        self.assert_(
            SAMLCredentialWalletTestCase.SITEA_ATTRIBUTEAUTHORITY_SAML_URI in \
            wallet.credentialsKeyedByURI)
        self.assert_(SAMLCredentialWalletTestCase.SITEA_SAML_ISSUER_NAME in \
                     wallet.credentials)
        
        assertion = wallet.credentials[
            SAMLCredentialWalletTestCase.SITEA_SAML_ISSUER_NAME
        ].credential
        
        print("SAML Assertion:\n%s" % 
              prettyPrint(AssertionElementTree.toXML(assertion)))
    
    def test02VerifyCredential(self):
        wallet = SAMLCredentialWallet()
        self.assert_(wallet.isValidCredential(self.assertion))
        
        expiredAssertion = self._createAssertion(
                                timeNow=datetime.utcnow() - timedelta(hours=24))
                                
        self.assert_(not wallet.isValidCredential(expiredAssertion))
        
        futureAssertion = self._createAssertion(
                                timeNow=datetime.utcnow() + timedelta(hours=24))

        self.assert_(not wallet.isValidCredential(futureAssertion))
        
    def test03AuditCredential(self):
        # Add a short lived credential and ensure it's removed when an audit
        # is carried to prune expired credentials
        shortExpiryAssertion = self._createAssertion(validityDuration=1)
        wallet = SAMLCredentialWallet()
        wallet.addCredential(shortExpiryAssertion)
        
        self.assert_(len(wallet.credentials) == 1)
        sleep(2)
        wallet.audit()
        self.assert_(len(wallet.credentials) == 0)

    def test04ClockSkewTolerance(self):
        # Add a short lived credential but with the wallet set to allow for
        # a clock skew of 
        shortExpiryAssertion = self._createAssertion(validityDuration=1)
        wallet = SAMLCredentialWallet()
        
        # Set a tolerance of five seconds
        wallet.clockSkewTolerance = 5.*60*60
        wallet.addCredential(shortExpiryAssertion)
        
        self.assert_(len(wallet.credentials) == 1)
        sleep(2)
        wallet.audit()
        self.assert_(len(wallet.credentials) == 1)
        
    def test05ReplaceCredential(self):
        # Replace an existing credential from a given institution with a more
        # up to date one
        wallet = self._addCredential()
        self.assert_(len(wallet.credentials) == 1)
        
        newAssertion = self._createAssertion()  

        wallet.addCredential(newAssertion)
        self.assert_(len(wallet.credentials) == 1)
        self.assert_(newAssertion.conditions.notOnOrAfter == \
                     wallet.credentials[
                        SAMLCredentialWalletTestCase.SITEA_SAML_ISSUER_NAME
                    ].credential.conditions.notOnOrAfter)
        
    def test06CredentialsFromSeparateSites(self):
        wallet = self._addCredential()
        wallet.addCredential(self._createAssertion(issuerName="MySite"))
        self.assert_(len(wallet.credentials) == 2)

    def test07Pickle(self):
        wallet = self._addCredential()
        outFile = open(SAMLCredentialWalletTestCase.PICKLE_FILEPATH, 'w')
        pickle.dump(wallet, outFile)
        outFile.close()
        
        inFile = open(SAMLCredentialWalletTestCase.PICKLE_FILEPATH)
        unpickledWallet = pickle.load(inFile)
        self.assert_(unpickledWallet.credentialsKeyedByURI.get(
            SAMLCredentialWalletTestCase.SITEA_ATTRIBUTEAUTHORITY_SAML_URI))
        
        self.assert_(unpickledWallet.credentials.items()[0][1].issuerName == \
                     BaseTestCase.SITEA_SAML_ISSUER_NAME)

    def test08CreateFromConfig(self):
        wallet = SAMLCredentialWallet.fromConfig(
                                SAMLCredentialWalletTestCase.CONFIG_FILEPATH)
        self.assert_(wallet.clockSkewTolerance == timedelta(seconds=0.01))
        self.assert_(wallet.userId == 'https://openid.localhost/philip.kershaw')
        
if __name__ == "__main__":
    unittest.main()        
