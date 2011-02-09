#!/usr/bin/env python
"""NDG XML Security unit tests

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
from ndg.security.common.XMLSec import XMLSecDoc

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_XMLSECDOC_UNITTEST_DIR'], file)

class XMLSecDocTestCase(unittest.TestCase):
    
    def setUp(self):
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_XMLSECDOC_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_XMLSECDOC_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))
        
        configParser = SafeConfigParser()
        configFilePath = jnPath(os.environ['NDGSEC_XMLSECDOC_UNITTEST_DIR'],
                                "xmlSecDocTest.cfg")
        configParser.read(configFilePath)
        
        self.cfg = {}
        for section in configParser.sections():
            self.cfg[section] = dict(configParser.items(section))

        self.strXML = """<?xml version="1.0"?>
<attributeCertificate targetNamespace="urn:ndg:security">
    <acInfo>
        <version>1.0</version>
        <holder>/CN=gabriel/O=NDG/OU=Gabriel</holder>
        <issuer>/CN=AttributeAuthority/O=NDG/OU=Gabriel</issuer>
        <issuerName>Gabriel</issuerName>
        <issuerSerialNumber>42</issuerSerialNumber>
        <validity>
            <notBefore>2006 07 17 08 44 03</notBefore>
            <notAfter>2006 07 17 16 44 03</notAfter>
        </validity>
        <attributes>
            <roleSet>
                <role>
                    <name>staff</name>
                </role>
                <role>
                    <name>postdoc</name>
                </role>
                <role>
                    <name>academic</name>
                </role>
            </roleSet>
        </attributes>
        <provenance>original</provenance>
    </acInfo>
</attributeCertificate>
"""          
        self.xmlSecDoc = XMLSecDoc()
        
    def test1Parse(self):
        '''test1Parse: parse an XML document'''
            
        self.xmlSecDoc.parse(self.strXML)


    def test2Sign(self): 
        '''test2Sign: sign document'''
            
        self.xmlSecDoc.filePath = xpdVars(self.cfg['test2Sign']['filepath'])
        self.xmlSecDoc.certFilePathList = \
                                xpdVars(self.cfg['test2Sign']['certfile'])
        self.xmlSecDoc.signingKeyFilePath = \
                                xpdVars(self.cfg['test2Sign']['keyfile'])
        
        keyPwd = self.cfg['test2Sign'].get('keypwd')
        if keyPwd is None:
            self.xmlSecDoc.signingKeyPwd = \
                getpass.getpass(prompt="\ntest2Sign private key password: ")
        
        self.xmlSecDoc.applyEnvelopedSignature(xmlTxt=self.strXML)
        self.xmlSecDoc.write()
    
    
    def test3Write(self):
        '''test3Write: write document'''
            
        self.test1Parse()
        self.xmlSecDoc.filePath = xpdVars(self.cfg['test3Write']['filepath'])
        self.xmlSecDoc.write()

        
    def test4Read(self):
        '''test4Read: read document'''
            
        self.xmlSecDoc.filePath = xpdVars(self.cfg['test4Read']['filepath'])
        self.xmlSecDoc.read()


    def test5Verify(self):
        '''test5Verify: check signature of XML document'''
            
        self.xmlSecDoc.filePath = xpdVars(self.cfg['test5Verify']['filepath'])
        self.xmlSecDoc.certFilePathList = [xpdVars(file) for file in \
                        self.cfg['test5Verify']['certfilepathlist'].split()]
        self.xmlSecDoc.read()
        self.xmlSecDoc.verifyEnvelopedSignature()
        
 
#_____________________________________________________________________________       
class XMLSecDocTestSuite(unittest.TestSuite):
    def __init__(self):
        map = map(XMLSecDocTestCase,
                  (
                   "test1Parse",
                   "test2Sign", 
                   "test3Write", 
                   "test4Read", 
                   "test5Verify"
                  ))
        unittest.TestSuite.__init__(self, map)
                                        
if __name__ == "__main__":
    unittest.main()
