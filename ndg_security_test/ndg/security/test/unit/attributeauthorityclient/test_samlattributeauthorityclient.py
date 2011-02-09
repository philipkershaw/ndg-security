#!/usr/bin/env python
"""NDG Attribute Authority SAML SOAP Binding client unit tests

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/02/10 (moved from test_attributeauthorityclient)"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
import os
from datetime import datetime
from uuid import uuid4
from xml.etree import ElementTree

from ndg.saml.common import SAMLVersion
from ndg.saml.common.xml import SAMLConstants
from ndg.saml.xml.etree import AttributeQueryElementTree, ResponseElementTree
from ndg.saml.saml2.core import (Subject, Issuer, Attribute, NameID, 
                                 AttributeQuery, StatusCode, 
                                 XSStringAttributeValue)

from ndg.saml.saml2.binding.soap.client import SOAPBinding
from ndg.saml.saml2.binding.soap.client.attributequery import (
                                        AttributeQuerySOAPBinding, 
                                        AttributeQuerySslSOAPBinding)
from ndg.security.common.saml_utils.esg import (EsgSamlNamespaces,
                                                EsgDefaultQueryAttributes)
from ndg.security.test.unit.attributeauthorityclient import \
                                        AttributeAuthorityClientBaseTestCase
from ndg.security.common.utils.etree import prettyPrint

   
class AttributeAuthoritySAMLInterfaceTestCase(
                                        AttributeAuthorityClientBaseTestCase):
    """NDG Attribute Authority SAML SOAP Binding client unit tests"""
    HERE_DIR = os.path.dirname(__file__)
    CONFIG_FILENAME = 'test_samlattributeauthorityclient.cfg'
    CONFIG_FILEPATH = os.path.join(HERE_DIR, CONFIG_FILENAME)
    
    def __init__(self, *arg, **kw):
        super(AttributeAuthoritySAMLInterfaceTestCase, self).__init__(*arg, 
                                                                      **kw)
        
        # Run same config but on two different ports - one HTTP and one HTTPS
        self.startSiteAAttributeAuthority()
        self.startSiteAAttributeAuthority(withSSL=True, port=5443)
       
    def test01AttributeQuery(self):
        _cfg = self.cfg['test01AttributeQuery']
        
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = "/CN=Authorisation Service/O=Site A"    
                        
        attributeQuery.subject = Subject()
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = EsgSamlNamespaces.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = _cfg['subject']
        xsStringNs = SAMLConstants.XSD_NS+"#"+\
                                        XSStringAttributeValue.TYPE_LOCAL_NAME
        fnAttribute = Attribute()
        fnAttribute.name = EsgSamlNamespaces.FIRSTNAME_ATTRNAME
        fnAttribute.nameFormat = xsStringNs
        fnAttribute.friendlyName = "FirstName"

        attributeQuery.attributes.append(fnAttribute)
    
        lnAttribute = Attribute()
        lnAttribute.name = EsgSamlNamespaces.LASTNAME_ATTRNAME
        lnAttribute.nameFormat = xsStringNs
        lnAttribute.friendlyName = "LastName"

        attributeQuery.attributes.append(lnAttribute)
    
        emailAddressAttribute = Attribute()
        emailAddressAttribute.name = EsgSamlNamespaces.EMAILADDRESS_ATTRNAME
        emailAddressAttribute.nameFormat = xsStringNs
        emailAddressAttribute.friendlyName = "emailAddress"
        
        attributeQuery.attributes.append(emailAddressAttribute) 

        siteAAttribute = Attribute()
        siteAAttribute.name = _cfg['siteAttributeName']
        siteAAttribute.nameFormat = xsStringNs
        
        attributeQuery.attributes.append(siteAAttribute) 

        binding = SOAPBinding()
        binding.serialise = AttributeQueryElementTree.toXML
        binding.deserialise = ResponseElementTree.fromXML
        response = binding.send(attributeQuery, _cfg['uri'])
        
        self.assert_(response.status.statusCode.value==StatusCode.SUCCESS_URI)
        
        # Check Query ID matches the query ID the service received
        self.assert_(response.inResponseTo == attributeQuery.id)
        
        now = datetime.utcnow()
        self.assert_(response.issueInstant < now)
        self.assert_(response.assertions[-1].issueInstant < now)        
        self.assert_(response.assertions[-1].conditions.notBefore < now) 
        self.assert_(response.assertions[-1].conditions.notOnOrAfter > now)
         
        samlResponseElem = ResponseElementTree.toXML(response)
        
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
             
    def test02AttributeQueryInvalidIssuer(self):
        _cfg = self.cfg['test02AttributeQueryInvalidIssuer']
        
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = "/O=Invalid Site/CN=PDP"    
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = EsgSamlNamespaces.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = _cfg['subject']
        xsStringNs = SAMLConstants.XSD_NS+"#"+\
                                        XSStringAttributeValue.TYPE_LOCAL_NAME

        siteAAttribute = Attribute()
        siteAAttribute.name = _cfg['siteAttributeName']
        siteAAttribute.nameFormat = xsStringNs
        
        attributeQuery.attributes.append(siteAAttribute) 

        binding = SOAPBinding()
        binding.serialise = AttributeQueryElementTree.toXML
        binding.deserialise = ResponseElementTree.fromXML
        response = binding.send(attributeQuery, _cfg['uri'])

        samlResponseElem = ResponseElementTree.toXML(response)
        
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
        
        self.assert_(
            response.status.statusCode.value==StatusCode.REQUEST_DENIED_URI)
                    
    def test03AttributeQueryUnknownSubject(self):
        _cfg = self.cfg['test03AttributeQueryUnknownSubject']
        
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = "/CN=Authorisation Service/O=Site A"    
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = EsgSamlNamespaces.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = _cfg['subject']
        xsStringNs = SAMLConstants.XSD_NS+"#"+\
                                        XSStringAttributeValue.TYPE_LOCAL_NAME

        siteAAttribute = Attribute()
        siteAAttribute.name = _cfg['siteAttributeName']
        siteAAttribute.nameFormat = xsStringNs
        
        attributeQuery.attributes.append(siteAAttribute) 

        binding = SOAPBinding()
        binding.serialise = AttributeQueryElementTree.toXML
        binding.deserialise = ResponseElementTree.fromXML
        response = binding.send(attributeQuery, _cfg['uri'])
        
        samlResponseElem = ResponseElementTree.toXML(response)
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
        
        self.assert_(
            response.status.statusCode.value==StatusCode.UNKNOWN_PRINCIPAL_URI)
             
    def test04AttributeQueryInvalidAttrName(self):
        thisSection = 'test04AttributeQueryInvalidAttrName'
        _cfg = self.cfg[thisSection]
        
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = "/CN=Authorisation Service/O=Site A"    
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = EsgSamlNamespaces.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = _cfg['subject']
        xsStringNs = SAMLConstants.XSD_NS+"#"+\
                                        XSStringAttributeValue.TYPE_LOCAL_NAME

        invalidAttribute = Attribute()
        invalidAttribute.name = "myInvalidAttributeName"
        invalidAttribute.nameFormat = xsStringNs
        
        attributeQuery.attributes.append(invalidAttribute) 

        binding = SOAPBinding.fromConfig(
                     AttributeAuthoritySAMLInterfaceTestCase.CONFIG_FILEPATH, 
                     prefix='saml.', 
                     section=thisSection)
        response = binding.send(attributeQuery, _cfg['uri'])
        
        samlResponseElem = ResponseElementTree.toXML(response)
        
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
        
        self.assert_(response.status.statusCode.value==\
                     StatusCode.INVALID_ATTR_NAME_VALUE_URI)
        
    def test05AttributeQuerySOAPBindingInterface(self):
        _cfg = self.cfg['test05AttributeQuerySOAPBindingInterface']
        
        binding = AttributeQuerySOAPBinding()
        
        binding.subjectID = AttributeAuthoritySAMLInterfaceTestCase.OPENID_URI
        binding.subjectIdFormat = EsgSamlNamespaces.NAMEID_FORMAT
        binding.issuerName = \
            str(AttributeAuthoritySAMLInterfaceTestCase.VALID_REQUESTOR_IDS[0])
        binding.issuerFormat = Issuer.X509_SUBJECT
        
        binding.queryAttributes = EsgDefaultQueryAttributes.ATTRIBUTES
        
        response = binding.send(uri=_cfg['uri'])
        samlResponseElem = ResponseElementTree.toXML(response)
        
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
        
        self.assert_(response.status.statusCode.value==StatusCode.SUCCESS_URI)

    def test06AttributeQueryFromConfig(self):
        thisSection = 'test06AttributeQueryFromConfig'
        _cfg = self.cfg[thisSection]
        
        binding = AttributeQuerySOAPBinding.fromConfig(self.cfgFilePath, 
                                                       section=thisSection,
                                                       prefix='attributeQuery.')
        binding.subjectID = _cfg['subject']
        response = binding.send(uri=_cfg['uri'])
        samlResponseElem = ResponseElementTree.toXML(response)
        
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
        
        self.assert_(response.status.statusCode.value==StatusCode.SUCCESS_URI)
        
    def test07AttributeQuerySslSOAPBindingInterface(self):
        thisSection = 'test07AttributeQuerySslSOAPBindingInterface'
        _cfg = self.cfg[thisSection]
        
        binding = AttributeQuerySslSOAPBinding.fromConfig(self.cfgFilePath, 
                                                       section=thisSection,
                                                       prefix='attributeQuery.')
        
        binding.subjectID = _cfg['subject']
        response = binding.send(uri=_cfg['uri'])
        samlResponseElem = ResponseElementTree.toXML(response)
        
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
        
        self.assert_(response.status.statusCode.value==StatusCode.SUCCESS_URI)

       
if __name__ == "__main__":
    unittest.main()
