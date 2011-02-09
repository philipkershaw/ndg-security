#!/usr/bin/env python
"""NDG Attribute Authority

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/12/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import unittest
import os
import sys
import getpass
import re
import logging
logging.basicConfig(level=logging.DEBUG)

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file:jnPath(os.environ['NDGSEC_AA_UNITTEST_DIR'], file)

from ndg.security.test.unit import BaseTestCase

from ndg.security.common.utils.configfileparsers import (
    CaseSensitiveConfigParser)
from ndg.security.server.attributeauthority import (AttributeAuthority, 
    AttributeAuthorityNoMatchingRoleInTrustedHosts, 
    SQLAlchemyAttributeInterface, InvalidAttributeFormat)

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
            
        self.aa = AttributeAuthority.fromPropertyFile(
                                            self.cfg['setUp']['propFilePath'])

    _mkSiteBAttributeAuthority = lambda self: \
        AttributeAuthority.fromPropertyFile(
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
        thisSection = self.cfg[
                            'test03GetTrustedHostInfoWithNoMatchingRoleFound']
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


from warnings import warn
from uuid import uuid4
from datetime import datetime
from saml.saml2.core import (Response, Attribute, SAMLVersion, Subject, NameID,
                             Issuer, AttributeQuery, XSStringAttributeValue, 
                             Status, StatusMessage, StatusCode)
from saml.xml import XMLConstants
from ndg.security.common.saml_utils.esg import EsgSamlNamespaces


class SQLAlchemyAttributeInterfaceTestCase(BaseTestCase):
    SAML_SUBJECT_SQLQUERY = ("select count(*) from users where openid = "
                             "'${userId}'")
    
    SAML_FIRSTNAME_SQLQUERY = ("select firstname from users where openid = "
                               "'${userId}'")
            
    SAML_LASTNAME_SQLQUERY = ("select lastname from users where openid = "
                              "'${userId}'")
        
    SAML_EMAILADDRESS_SQLQUERY = ("select emailaddress from users where "
                                  "openid = '${userId}'")
        
    SAML_ATTRIBUTES_SQLQUERY = ("select attributename from attributes, users "
                                "where users.openid = '${userId}' and "
                                "attributes.username = users.username")
                                
    def __init__(self, *arg, **kw):
        super(SQLAlchemyAttributeInterfaceTestCase, self).__init__(*arg, **kw)
        self.skipTests = False
        try:
            import sqlalchemy

        except NotImplementedError:
            # Don't proceed with tests because SQLAlchemy is not installed
            warn("Skipping SQLAlchemyAttributeInterfaceTestCase because "
                 "SQLAlchemy is not installed")
            self.skipTests = True
        
        if 'NDGSEC_AA_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_AA_UNITTEST_DIR'
                       ] = os.path.abspath(os.path.dirname(__file__))
            
        self.initDb()
        
    def test01TrySamlAttribute2SqlQuery__setattr__(self):
        if self.skipTests:
            return
        
        attributeInterface = SQLAlchemyAttributeInterface()
        
        # Define queries for SAML attribute names
        attributeInterface.samlAttribute2SqlQuery_firstName = '"%s" "%s"' % (
            EsgSamlNamespaces.FIRSTNAME_ATTRNAME,                                                               
            SQLAlchemyAttributeInterfaceTestCase.SAML_FIRSTNAME_SQLQUERY)
            
        setattr(attributeInterface, 
                'samlAttribute2SqlQuery.lastName',
                "%s %s" % (EsgSamlNamespaces.LASTNAME_ATTRNAME,
                SQLAlchemyAttributeInterfaceTestCase.SAML_LASTNAME_SQLQUERY))
        
        attributeInterface.samlAttribute2SqlQuery[
            EsgSamlNamespaces.EMAILADDRESS_ATTRNAME] = (
                SQLAlchemyAttributeInterfaceTestCase.SAML_EMAILADDRESS_SQLQUERY)
        
        attributeInterface.samlAttribute2SqlQuery[
            SQLAlchemyAttributeInterfaceTestCase.ATTRIBUTE_NAMES[0]] = (
            SQLAlchemyAttributeInterfaceTestCase.SAML_ATTRIBUTES_SQLQUERY)
        
    def test02SetProperties(self):
        # test setProperties interface for instance attribute assignment
        if self.skipTests:
            return
        
        # samlAttribute2SqlQuery* suffixes have no particular requirement
        # only that they are unique and start with an underscore or period.
        properties = {
            'connectionString': 
                SQLAlchemyAttributeInterfaceTestCase.DB_CONNECTION_STR,
            
            'samlSubjectSqlQuery':
                SQLAlchemyAttributeInterfaceTestCase.SAML_SUBJECT_SQLQUERY,
                
            'samlAttribute2SqlQuery.firstname': '"%s" "%s"' % (
                EsgSamlNamespaces.FIRSTNAME_ATTRNAME,
                SQLAlchemyAttributeInterfaceTestCase.SAML_FIRSTNAME_SQLQUERY),
            
            'samlAttribute2SqlQuery.blah': '"%s" "%s"' % (
                EsgSamlNamespaces.LASTNAME_ATTRNAME,
                SQLAlchemyAttributeInterfaceTestCase.SAML_LASTNAME_SQLQUERY),
        
            'samlAttribute2SqlQuery.3': '%s "%s"' % (
            EsgSamlNamespaces.EMAILADDRESS_ATTRNAME,
            SQLAlchemyAttributeInterfaceTestCase.SAML_EMAILADDRESS_SQLQUERY),
        
            'samlAttribute2SqlQuery_0': '%s %s' % (
                SQLAlchemyAttributeInterfaceTestCase.ATTRIBUTE_NAMES[0],
                SQLAlchemyAttributeInterfaceTestCase.SAML_ATTRIBUTES_SQLQUERY),
            
            'samlValidRequestorDNs': ('/O=STFC/OU=CEDA/CN=AuthorisationService',
                                      '/O=ESG/OU=NCAR/CN=Gateway'),
            'samlAssertionLifetime': 86400,

        }
        attributeInterface = SQLAlchemyAttributeInterface()
        attributeInterface.setProperties(**properties)
        
        self.assert_(
            attributeInterface.samlAttribute2SqlQuery[
                EsgSamlNamespaces.FIRSTNAME_ATTRNAME] == \
            SQLAlchemyAttributeInterfaceTestCase.SAML_FIRSTNAME_SQLQUERY)
        
        self.assert_(attributeInterface.connectionString == \
                     SQLAlchemyAttributeInterfaceTestCase.DB_CONNECTION_STR)
        
        # Test constructor setting properties
        attributeInterface2 = SQLAlchemyAttributeInterface(**properties)
        self.assert_(attributeInterface2.samlAssertionLifetime.days == 1)

    def test03FromConfigFile(self):
        if self.skipTests:
            return
        cfgParser = CaseSensitiveConfigParser()
        cfgFilePath = mkPath('test_sqlalchemyattributeinterface.cfg')
        cfgParser.read(cfgFilePath)
        
        cfg = dict(cfgParser.items('DEFAULT'))
        attributeInterface = SQLAlchemyAttributeInterface()
        attributeInterface.setProperties(prefix='attributeInterface.', **cfg)
        
        self.assert_(
            attributeInterface.samlAttribute2SqlQuery[
                EsgSamlNamespaces.EMAILADDRESS_ATTRNAME] == \
            SQLAlchemyAttributeInterfaceTestCase.SAML_EMAILADDRESS_SQLQUERY)

    def test04SamlAttributeQuery(self):
        if self.skipTests:
            return
        
        # Prepare a client query
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = '/O=ESG/OU=NCAR/CN=Gateway'
                        
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = EsgSamlNamespaces.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = \
                                SQLAlchemyAttributeInterfaceTestCase.OPENID_URI
        
        fnAttribute = Attribute()
        fnAttribute.name = EsgSamlNamespaces.FIRSTNAME_ATTRNAME
        fnAttribute.nameFormat = XSStringAttributeValue.DEFAULT_FORMAT
        fnAttribute.friendlyName = "FirstName"

        attributeQuery.attributes.append(fnAttribute)
    
        lnAttribute = Attribute()
        lnAttribute.name = EsgSamlNamespaces.LASTNAME_ATTRNAME
        lnAttribute.nameFormat = XSStringAttributeValue.DEFAULT_FORMAT
        lnAttribute.friendlyName = "LastName"

        attributeQuery.attributes.append(lnAttribute)
    
        emailAddressAttribute = Attribute()
        emailAddressAttribute.name = EsgSamlNamespaces.EMAILADDRESS_ATTRNAME
        emailAddressAttribute.nameFormat = XSStringAttributeValue.DEFAULT_FORMAT
        emailAddressAttribute.friendlyName = "EmailAddress"

        attributeQuery.attributes.append(emailAddressAttribute)                                   
    
        authzAttribute = Attribute()
        authzAttribute.name = \
            SQLAlchemyAttributeInterfaceTestCase.ATTRIBUTE_NAMES[0]
        authzAttribute.nameFormat = XSStringAttributeValue.DEFAULT_FORMAT
        authzAttribute.friendlyName = "authz"

        attributeQuery.attributes.append(authzAttribute)                                   
        
        # Add the response - the interface will populate with an assertion as
        # appropriate
        samlResponse = Response()
        
        samlResponse.issueInstant = datetime.utcnow()
        samlResponse.id = str(uuid4())
        samlResponse.issuer = Issuer()
        
        # Initialise to success status but reset on error
        samlResponse.status = Status()
        samlResponse.status.statusCode = StatusCode()
        samlResponse.status.statusMessage = StatusMessage()
        samlResponse.status.statusCode.value = StatusCode.SUCCESS_URI
        
        # Nb. SAML 2.0 spec says issuer format must be omitted
        samlResponse.issuer.value = "CEDA"
        
        samlResponse.inResponseTo = attributeQuery.id
        
        # Set up the interface object
        
        # Define queries for SAML attribute names
        samlAttribute2SqlQuery = {
            EsgSamlNamespaces.FIRSTNAME_ATTRNAME: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_FIRSTNAME_SQLQUERY,
            
            EsgSamlNamespaces.LASTNAME_ATTRNAME: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_LASTNAME_SQLQUERY,
        
            EsgSamlNamespaces.EMAILADDRESS_ATTRNAME: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_EMAILADDRESS_SQLQUERY,
        
            SQLAlchemyAttributeInterfaceTestCase.ATTRIBUTE_NAMES[0]: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_ATTRIBUTES_SQLQUERY                    
        }
        
        attributeInterface = SQLAlchemyAttributeInterface(
                                samlAttribute2SqlQuery=samlAttribute2SqlQuery)
        
        attributeInterface.connectionString = \
                        SQLAlchemyAttributeInterfaceTestCase.DB_CONNECTION_STR
                
        attributeInterface.samlValidRequestorDNs = (
            '/O=STFC/OU=CEDA/CN=AuthorisationService',
            '/O=ESG/OU=NCAR/CN=Gateway')
        
        attributeInterface.setProperties(samlAssertionLifetime=28800.,
                                issuerName='/CN=Attribute Authority/O=Site A')
        
        attributeInterface.samlSubjectSqlQuery = (
            SQLAlchemyAttributeInterfaceTestCase.SAML_SUBJECT_SQLQUERY)
        
        # Make the query
        attributeInterface.getAttributes(attributeQuery, samlResponse)
        
        self.assert_(
                samlResponse.status.statusCode.value == StatusCode.SUCCESS_URI)
        self.assert_(samlResponse.inResponseTo == attributeQuery.id)
        self.assert_(samlResponse.assertions[0].subject.nameID.value == \
                     attributeQuery.subject.nameID.value)
        self.assert_(
            samlResponse.assertions[0].attributeStatements[0].attributes[1
                ].attributeValues[0].value == 'Kershaw')
        
        self.assert_(
            len(samlResponse.assertions[0].attributeStatements[0].attributes[3
                ].attributeValues) == \
                    SQLAlchemyAttributeInterfaceTestCase.N_ATTRIBUTE_VALUES)

    def test04SamlAttributeQuery(self):
        if self.skipTests:
            return
        
        # Prepare a client query
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = '/O=ESG/OU=NCAR/CN=Gateway'
                        
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = EsgSamlNamespaces.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = \
                                SQLAlchemyAttributeInterfaceTestCase.OPENID_URI
    
        emailAddressAttribute = Attribute()
        emailAddressAttribute.name = EsgSamlNamespaces.EMAILADDRESS_ATTRNAME
        emailAddressAttribute.nameFormat = "InvalidFormat"
        emailAddressAttribute.friendlyName = "EmailAddress"

        attributeQuery.attributes.append(emailAddressAttribute)                                   
    
        authzAttribute = Attribute()
        authzAttribute.name = \
            SQLAlchemyAttributeInterfaceTestCase.ATTRIBUTE_NAMES[0]
        authzAttribute.nameFormat = XSStringAttributeValue.DEFAULT_FORMAT
        authzAttribute.friendlyName = "authz"

        attributeQuery.attributes.append(authzAttribute)                                   
        
        # Add the response - the interface will populate with an assertion as
        # appropriate
        samlResponse = Response()
        
        samlResponse.issueInstant = datetime.utcnow()
        samlResponse.id = str(uuid4())
        samlResponse.issuer = Issuer()
        
        # Initialise to success status but reset on error
        samlResponse.status = Status()
        samlResponse.status.statusCode = StatusCode()
        samlResponse.status.statusMessage = StatusMessage()
        samlResponse.status.statusCode.value = StatusCode.SUCCESS_URI
        
        # Nb. SAML 2.0 spec says issuer format must be omitted
        samlResponse.issuer.value = "CEDA"
        
        samlResponse.inResponseTo = attributeQuery.id
        
        # Set up the interface object
        
        # Define queries for SAML attribute names
        samlAttribute2SqlQuery = {
            EsgSamlNamespaces.FIRSTNAME_ATTRNAME: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_FIRSTNAME_SQLQUERY,
            
            EsgSamlNamespaces.LASTNAME_ATTRNAME: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_LASTNAME_SQLQUERY,
        
            EsgSamlNamespaces.EMAILADDRESS_ATTRNAME: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_EMAILADDRESS_SQLQUERY,
        
            SQLAlchemyAttributeInterfaceTestCase.ATTRIBUTE_NAMES[0]: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_ATTRIBUTES_SQLQUERY                    
        }
        
        attributeInterface = SQLAlchemyAttributeInterface(
                                samlAttribute2SqlQuery=samlAttribute2SqlQuery)
        
        attributeInterface.connectionString = \
                        SQLAlchemyAttributeInterfaceTestCase.DB_CONNECTION_STR
                
        attributeInterface.samlValidRequestorDNs = (
            '/O=STFC/OU=CEDA/CN=AuthorisationService',
            '/O=ESG/OU=NCAR/CN=Gateway')
        
        attributeInterface.setProperties(samlAssertionLifetime=28800.,
                                issuerName='/CN=Attribute Authority/O=Site A')
        
        attributeInterface.samlSubjectSqlQuery = (
            SQLAlchemyAttributeInterfaceTestCase.SAML_SUBJECT_SQLQUERY)
        
        # Make the query
        try:
            attributeInterface.getAttributes(attributeQuery, samlResponse)
        except InvalidAttributeFormat:
            print("PASSED: caught InvalidAttributeFormat exception")
        else:
            self.fail("Expecting InvalidAttributeFormat exception")
        
if __name__ == "__main__":
    unittest.main()
