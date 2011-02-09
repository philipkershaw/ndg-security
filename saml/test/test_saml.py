"""SAML unit test package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "21/07/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import logging
logging.basicConfig(level=logging.DEBUG)
    
from datetime import datetime, timedelta
from uuid import uuid4
from cStringIO import StringIO

import unittest

from xml.etree.ElementTree import iselement
from xml.etree import ElementTree

from saml.saml2.core import (SAMLVersion, Attribute, AttributeStatement, 
                             Assertion, AttributeQuery, Response, Issuer, 
                             Subject, NameID, StatusCode, 
                             StatusMessage, Status, Conditions, 
                             XSStringAttributeValue)

from saml.common.xml import SAMLConstants
from saml.xml.etree import (prettyPrint, AssertionElementTree, 
                            AttributeQueryElementTree, ResponseElementTree)


class SAMLUtil(object):
    """SAML utility class based on ANL examples for Earth System Grid:
    http://www.ci.uchicago.edu/wiki/bin/view/ESGProject/ESGSAMLAttributes#ESG_Attribute_Service
    """
    
    def __init__(self):
        """Set-up ESG core attributes, Group/Role and miscellaneous 
        attributes lists
        """
        self.firstName = None
        self.lastName = None
        self.emailAddress = None
        
        self.__miscAttrList = []
    
    def addAttribute(self, name, value):
        """Add a generic attribute
        @type name: basestring
        @param name: attribute name
        @type value: basestring
        @param value: attribute value
        """
        self.__miscAttrList.append((name, value))

    def buildAssertion(self):
        """Create a SAML Assertion containing ESG core attributes: First
        Name, Last Name, e-mail Address; ESG Group/Role type attributes
        and generic attributes
        @rtype: ndg.security.common.saml.Assertion
        @return: new SAML Assertion object
        """
        
        assertion = Assertion()
        assertion.version = SAMLVersion(SAMLVersion.VERSION_20)
        assertion.id = str(uuid4())
        assertion.issueInstant = datetime.utcnow()
        attributeStatement = AttributeStatement()
        
        for attribute in self.createAttributes():
            attributeStatement.attributes.append(attribute)
            
        assertion.attributeStatements.append(attributeStatement)
        
        return assertion

    def buildAttributeQuery(self, issuer, subjectNameID):
        """Make a SAML Attribute Query
        @type issuer: basestring
        @param issuer: attribute issuer name
        @type subjectNameID: basestring
        @param subjectNameID: identity to query attributes for
        """
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = issuer
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = "urn:esg:openid"
        attributeQuery.subject.nameID.value = subjectNameID
                                    
        attributeQuery.attributes = self.createAttributes()
        
        return attributeQuery
    
    def createAttributes(self):
        """Create SAML Attributes for use in an Assertion or AttributeQuery"""
        
        attributes = []
        if self.firstName is not None:    
            # special case handling for 'FirstName' attribute
            fnAttribute = Attribute()
            fnAttribute.name = "urn:esg:first:name"
            fnAttribute.nameFormat = "http://www.w3.org/2001/XMLSchema#string"
            fnAttribute.friendlyName = "FirstName"

            firstName = XSStringAttributeValue()
            firstName.value = self.firstName
            fnAttribute.attributeValues.append(firstName)

            attributes.append(fnAttribute)
        

        if self.lastName is not None:
            # special case handling for 'LastName' attribute
            lnAttribute = Attribute()
            lnAttribute.name = "urn:esg:last:name"
            lnAttribute.nameFormat = "http://www.w3.org/2001/XMLSchema#string"
            lnAttribute.friendlyName = "LastName"

            lastName = XSStringAttributeValue()
            lastName.value = self.lastName
            lnAttribute.attributeValues.append(lastName)

            attributes.append(lnAttribute)
        

        if self.emailAddress is not None:
            # special case handling for 'LastName' attribute
            emailAddressAttribute = Attribute()
            emailAddressAttribute.name = "urn:esg:email:address"
            emailAddressAttribute.nameFormat = SAMLConstants.XSD_NS+"#"+\
                                        XSStringAttributeValue.TYPE_LOCAL_NAME
            emailAddressAttribute.friendlyName = "emailAddress"

            emailAddress = XSStringAttributeValue()
            emailAddress.value = self.emailAddress
            emailAddressAttribute.attributeValues.append(emailAddress)

            attributes.append(emailAddressAttribute)
        
        for name, value in self.__miscAttrList:
            attribute = Attribute()
            attribute.name = name
            attribute.nameFormat = "http://www.w3.org/2001/XMLSchema#string"

            stringAttributeValue = XSStringAttributeValue()
            stringAttributeValue.value = value
            attribute.attributeValues.append(stringAttributeValue)

            attributes.append(attribute)
            
        return attributes


class SAMLTestCase(unittest.TestCase):
    """Test SAML implementation for use with CMIP5 federation"""
    
    def _createAssertionHelper(self):
        samlUtil = SAMLUtil()
        
        # ESG core attributes
        samlUtil.firstName = "Philip"
        samlUtil.lastName = "Kershaw"
        samlUtil.emailAddress = "p.j.k@somewhere"
        
        # BADC specific attributes
        badcRoleList = (
            'urn:badc:security:authz:1.0:attr:admin', 
            'urn:badc:security:authz:1.0:attr:rapid', 
            'urn:badc:security:authz:1.0:attr:coapec', 
            'urn:badc:security:authz:1.0:attr:midas', 
            'urn:badc:security:authz:1.0:attr:quest', 
            'urn:badc:security:authz:1.0:attr:staff'
        )
        for role in badcRoleList:
            samlUtil.addAttribute("urn:badc:security:authz:1.0:attr", role)
        
        # Make an assertion object
        assertion = samlUtil.buildAssertion()
        
        return assertion
        
    def test01CreateAssertion(self):
         
        assertion = self._createAssertionHelper()

        
        # Create ElementTree Assertion Element
        assertionElem = AssertionElementTree.toXML(assertion)
        
        self.assert_(iselement(assertionElem))
        
        # Serialise to output 
        xmlOutput = prettyPrint(assertionElem)       
        self.assert_(len(xmlOutput))
        
        print("\n"+"_"*80)
        print(xmlOutput)
        print("_"*80)

    def test02ParseAssertion(self):
        assertion = self._createAssertionHelper()
        
        # Create ElementTree Assertion Element
        assertionElem = AssertionElementTree.toXML(assertion)
        
        self.assert_(iselement(assertionElem))
        
        # Serialise to output 
        xmlOutput = prettyPrint(assertionElem)       
           
        print("\n"+"_"*80)
        print(xmlOutput)
        print("_"*80)
                
        assertionStream = StringIO()
        assertionStream.write(xmlOutput)
        assertionStream.seek(0)

        tree = ElementTree.parse(assertionStream)
        elem2 = tree.getroot()
        
        assertion2 = AssertionElementTree.fromXML(elem2)
        self.assert_(assertion2)
        
    def test03CreateAttributeQuery(self):
        samlUtil = SAMLUtil()
        samlUtil.firstName = ''
        samlUtil.lastName = ''
        samlUtil.emailAddress = ''
        attributeQuery = samlUtil.buildAttributeQuery(
                        "/O=NDG/OU=BADC/CN=attributeauthority.badc.rl.ac.uk",
                        "https://openid.localhost/philip.kershaw")
        
        elem = AttributeQueryElementTree.toXML(attributeQuery)        
        xmlOutput = prettyPrint(elem)
           
        print("\n"+"_"*80)
        print(xmlOutput)
        print("_"*80)

    def test04ParseAttributeQuery(self):
        samlUtil = SAMLUtil()
        samlUtil.firstName = ''
        samlUtil.lastName = ''
        samlUtil.emailAddress = ''
        attributeQuery = samlUtil.buildAttributeQuery(
                        "/O=NDG/OU=BADC/CN=attributeauthority.badc.rl.ac.uk",
                        "https://openid.localhost/philip.kershaw")
        
        elem = AttributeQueryElementTree.toXML(attributeQuery)        
        xmlOutput = prettyPrint(elem)       
        print("\n"+"_"*80)
        print(xmlOutput)
                
        attributeQueryStream = StringIO()
        attributeQueryStream.write(xmlOutput)
        attributeQueryStream.seek(0)

        tree = ElementTree.parse(attributeQueryStream)
        elem2 = tree.getroot()
        
        attributeQuery2 = AttributeQueryElementTree.fromXML(elem2)
        self.assert_(attributeQuery2.id == attributeQuery.id)
        self.assert_(attributeQuery2.issuer.value==attributeQuery.issuer.value)
        self.assert_(attributeQuery2.subject.nameID.value == \
                     attributeQuery.subject.nameID.value)
        
        self.assert_(attributeQuery2.attributes[1].name == \
                     attributeQuery.attributes[1].name)
        
        xmlOutput2 = prettyPrint(elem2)       
        print("_"*80)
        print(xmlOutput2)
        print("_"*80)

    def test05CreateResponse(self):
        response = Response()
        response.issueInstant = datetime.utcnow()
        
        # Make up a request ID that this response is responding to
        response.inResponseTo = str(uuid4())
        response.id = str(uuid4())
        response.version = SAMLVersion(SAMLVersion.VERSION_20)
            
        response.issuer = Issuer()
        response.issuer.format = Issuer.X509_SUBJECT
        response.issuer.value = \
                        "/O=NDG/OU=BADC/CN=attributeauthority.badc.rl.ac.uk"
        
        response.status = Status()
        response.status.statusCode = StatusCode()
        response.status.statusCode.value = StatusCode.SUCCESS_URI
        response.status.statusMessage = StatusMessage()        
        response.status.statusMessage.value = "Response created successfully"
           
        assertion = self._createAssertionHelper()
        
        # Add a conditions statement for a validity of 8 hours
        assertion.conditions = Conditions()
        assertion.conditions.notBefore = datetime.utcnow()
        assertion.conditions.notOnOrAfter = assertion.conditions.notBefore + \
            timedelta(seconds=60*60*8)
        
        assertion.subject = Subject()  
        assertion.subject.nameID = NameID()
        assertion.subject.nameID.format = "urn:esg:openid"
        assertion.subject.nameID.value = \
                        "https://openid.localhost/philip.kershaw"    
            
        assertion.issuer = Issuer()
        assertion.issuer.format = Issuer.X509_SUBJECT
        assertion.issuer.value = \
                        "/O=NDG/OU=BADC/CN=attributeauthority.badc.rl.ac.uk"

        response.assertions.append(assertion)
        
        # Create ElementTree Assertion Element
        responseElem = ResponseElementTree.toXML(response)
        
        self.assert_(iselement(responseElem))
        
        # Serialise to output        
        xmlOutput = prettyPrint(responseElem)       
        self.assert_(len(xmlOutput))
        print("\n"+"_"*80)
        print(xmlOutput)
        print("_"*80)
    
if __name__ == "__main__":
    unittest.main()        
