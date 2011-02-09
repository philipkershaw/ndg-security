#!/usr/bin/env python
"""NDG XML Security unit tests for ElementTree based implementation

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "03/01/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

import unittest
import os
import sys
import getpass
import traceback

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath=lambda file: jnPath(os.environ['NDGSEC_XMLSEC_ETREE_UNITTEST_DIR'],file)

from ConfigParser import SafeConfigParser
from ndg.security.test import BaseTestCase
from ndg.security.common.xmlsec.etree import XMLSecDoc

class XMLSecDocTestCase(BaseTestCase):
    
    def setUp(self):
        super(XMLSecDocTestCase, self).setUp()
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_XMLSEC_ETREE_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_XMLSEC_ETREE_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))
        
        configParser = SafeConfigParser()
        configFilePath = jnPath(os.environ['NDGSEC_XMLSEC_ETREE_UNITTEST_DIR'],
                                "etree.cfg")
        configParser.read(configFilePath)
        
        self.cfg = {}
        for section in configParser.sections():
            self.cfg[section] = dict(configParser.items(section))

        self.strXML = """<saml:Assertion 
xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" 
Issuer="http://badc.nerc.ac.uk" 
MajorVersion="1" 
MinorVersion="1">
    <saml:Conditions NotAfter="y" NotBefore="x"/>
    <saml:AuthenticationStatement 
    AuthenticationInstant="..." AuthenticationMethod="...">
        <saml:Subject></saml:Subject>
    </saml:AuthenticationStatement>
    <saml:AttributeStatement>
        <saml:Subject></saml:Subject>
        <saml:Attribute 
        AttributeName="urn:mace:dir:attribute-def:eduPersonAffiliation" 
        AttributeNamespace="urn:mace:shibboleth:1.0:attributeNamespace:uri">
            <saml:AttributeValue>member</saml:AttributeValue>
            <saml:AttributeValue>student</saml:AttributeValue>
        </saml:Attribute>
    </saml:AttributeStatement>
</saml:Assertion>
"""          
        self.xmlSecDoc = XMLSecDoc()
        
    def test1Parse(self):
        '''test1Parse: parse an XML document'''
            
        self.xmlSecDoc.parse(self.strXML)


    def test2SignWithInclC14N(self): 
        '''test2SignWithInclC14N: sign document using inclusive
        Canonicalization'''
            
        self.xmlSecDoc.filePath = \
                    xpdVars(self.cfg['test2SignWithInclC14N']['filepath'])
        self.xmlSecDoc.certFilePathList = \
            xpdVars(self.cfg['test2SignWithInclC14N']['signingcertfilepath'])
        self.xmlSecDoc.signingKeyFilePath = \
            xpdVars(self.cfg['test2SignWithInclC14N']['signingprikeyfilepath'])

        keyPwd = self.cfg['test2SignWithInclC14N'].get('signingprikeypwd')
        if keyPwd is None:
            self.xmlSecDoc.signingKeyPwd = getpass.getpass(prompt=\
                                                "\ntest2SignWithInclC14N "
                                                "private key password: ")
        
        self.xmlSecDoc.applyEnvelopedSignature(xmlTxt=self.strXML)
        self.xmlSecDoc.write()
    
    def test3SignWithExclC14N(self): 
        '''test3SignWithExclC14N: sign document using exclusive 
        Canonicalization'''
            
        self.xmlSecDoc.filePath = \
                    xpdVars(self.cfg['test3SignWithExclC14N']['filepath'])
        self.xmlSecDoc.certFilePathList = \
            xpdVars(self.cfg['test3SignWithExclC14N']['signingcertfilepath'])
        self.xmlSecDoc.signingKeyFilePath = \
            xpdVars(self.cfg['test3SignWithExclC14N']['signingprikeyfilepath'])

        keyPwd = self.cfg['test3SignWithExclC14N'].get('signingprikeypwd')
        if keyPwd is None:
            self.xmlSecDoc.signingKeyPwd = getpass.getpass(prompt=\
                                            "\ntest3SignWithExclC14N "
                                            "private key password: ")
        
        self.xmlSecDoc.applyEnvelopedSignature(xmlTxt=self.strXML,
                                       refC14nKw=dict(exclusive=True),
                                       signedInfoC14nKw=dict(exclusive=True))
        self.xmlSecDoc.write() 
        
          
    def test4Write(self):
        '''test4Write: write document'''
            
        self.test1Parse()
        self.xmlSecDoc.filePath = xpdVars(self.cfg['test4Write']['filepath'])
        self.xmlSecDoc.write()

        
    def test5Read(self):
        '''test5Read: read document'''
            
        self.xmlSecDoc.filePath = xpdVars(self.cfg['test5Read']['filepath'])
        self.xmlSecDoc.read()


    def test6VerifyInclC14nDoc(self):
        '''test6VerifyInclC14nDoc: check signature of XML document'''
            
        self.xmlSecDoc.filePath = \
            xpdVars(self.cfg['test6VerifyInclC14nDoc']['filepath'])
        self.xmlSecDoc.certFilePathList = \
        xpdVars(self.cfg['test6VerifyInclC14nDoc']['certfilepathlist']).split()
        
        self.xmlSecDoc.read()
        self.xmlSecDoc.verifyEnvelopedSignature()


    def test7VerifyExclC14nDoc(self):
        '''test7VerifyExclC14nDoc: check signature of XML document'''
            
        self.xmlSecDoc.filePath = \
            xpdVars(self.cfg['test7VerifyExclC14nDoc']['filepath'])
        self.xmlSecDoc.certFilePathList = \
        xpdVars(self.cfg['test7VerifyExclC14nDoc']['certfilepathlist']).split()
        
        self.xmlSecDoc.read()
        self.xmlSecDoc.verifyEnvelopedSignature()
       
 
#_____________________________________________________________________________       
class XMLSecDocTestSuite(unittest.TestSuite):
    def __init__(self):
        map = map(XMLSecDocTestCase,
                  (
                   "test1Parse",
                   "test2SignWithInclC14N", 
                   "test3SignWithExclC14N",
                   "test4Write", 
                   "test5Read", 
                   "test6VerifyInclC14nDoc",
                   "test7VerifyExclC14nDoc"
                  ))
        unittest.TestSuite.__init__(self, map)
                                        
if __name__ == "__main__":
    unittest.main()
