#!/usr/bin/env python
"""Unit tests for WSGI SAML 2.0 SOAP Attribute Query Interface

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "21/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import unittest
import os
from uuid import uuid4
from datetime import datetime

import paste.fixture
from paste.deploy import loadapp

from cStringIO import StringIO

from saml.saml2.core import (Attribute, SAMLVersion, Subject, NameID, Issuer, 
                             AttributeQuery, XSStringAttributeValue, 
                             StatusCode)
from saml.xml import XMLConstants
from saml.xml.etree import AttributeQueryElementTree, ResponseElementTree

from ndg.security.common.soap.etree import SOAPEnvelope
from ndg.security.common.utils.etree import prettyPrint
from ndg.security.common.saml_utils.esg import EsgSamlNamespaces
  
    
class TestApp(object):
    def __init__(self, global_conf, **app_conf):
        pass
    
    def __call__(self, environ, start_response):
        response = "404 Not Found"
        start_response(response,
                       [('Content-length', str(len(response))),
                        ('Content-type', 'text/plain')])
                            
        return [response]


class SOAPAttributeInterfaceMiddlewareTestCase(unittest.TestCase):
    
    def __init__(self, *args, **kwargs):
        here_dir = os.path.dirname(os.path.abspath(__file__))
        wsgiapp = loadapp('config:test.ini', relative_to=here_dir)
        self.app = paste.fixture.TestApp(wsgiapp)
         
        unittest.TestCase.__init__(self, *args, **kwargs)

    def _createAttributeQuery(self, 
                        issuer="/O=Site A/CN=Authorisation Service",
                        subject="https://openid.localhost/philip.kershaw"):
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = issuer
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = EsgSamlNamespaces.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = subject
                                    
        
        # special case handling for 'FirstName' attribute
        fnAttribute = Attribute()
        fnAttribute.name = EsgSamlNamespaces.FIRSTNAME_ATTRNAME
        fnAttribute.nameFormat = "http://www.w3.org/2001/XMLSchema#string"
        fnAttribute.friendlyName = "FirstName"

        attributeQuery.attributes.append(fnAttribute)
    
        # special case handling for 'LastName' attribute
        lnAttribute = Attribute()
        lnAttribute.name = EsgSamlNamespaces.LASTNAME_ATTRNAME
        lnAttribute.nameFormat = "http://www.w3.org/2001/XMLSchema#string"
        lnAttribute.friendlyName = "LastName"

        attributeQuery.attributes.append(lnAttribute)
    
        # special case handling for 'LastName' attribute
        emailAddressAttribute = Attribute()
        emailAddressAttribute.name = EsgSamlNamespaces.EMAILADDRESS_ATTRNAME
        emailAddressAttribute.nameFormat = XMLConstants.XSD_NS+"#"+\
                                    XSStringAttributeValue.TYPE_LOCAL_NAME
        emailAddressAttribute.friendlyName = "emailAddress"

        attributeQuery.attributes.append(emailAddressAttribute)  

        return attributeQuery
    
    def _makeRequest(self, attributeQuery=None, **kw):
        """Convenience method to construct queries for tests"""
        
        if attributeQuery is None:
            attributeQuery = self._createAttributeQuery(**kw)
            
        elem = AttributeQueryElementTree.toXML(attributeQuery)
        soapRequest = SOAPEnvelope()
        soapRequest.create()
        soapRequest.body.elem.append(elem)
        
        request = soapRequest.serialize()
        
        return request
    
    def _getSAMLResponse(self, responseBody):
        """Deserialise response string into ElementTree element"""
        soapResponse = SOAPEnvelope()
        
        responseStream = StringIO()
        responseStream.write(responseBody)
        responseStream.seek(0)
        
        soapResponse.parse(responseStream)
        
        print("Parsed response ...")
        print(soapResponse.serialize())
#        print(prettyPrint(soapResponse.elem))
        
        response = ResponseElementTree.fromXML(soapResponse.body.elem[0])
        
        return response
    
    def test01ValidQuery(self):
        attributeQuery = self._createAttributeQuery()
        request = self._makeRequest(attributeQuery=attributeQuery)
        
        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
        response = self.app.post('/attributeauthority/saml', 
                                 params=request, 
                                 headers=header, 
                                 status=200)
        print("Response status=%d" % response.status)
        samlResponse = self._getSAMLResponse(response.body)

        self.assert_(samlResponse.status.statusCode.value == \
                     StatusCode.SUCCESS_URI)
        self.assert_(samlResponse.inResponseTo == attributeQuery.id)
        self.assert_(samlResponse.assertions[0].subject.nameID.value == \
                     attributeQuery.subject.nameID.value)

    def test02AttributeReleaseDenied(self):
        request = self._makeRequest(issuer="/O=Site B/CN=Authorisation Service")
        
        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
        
        response = self.app.post('/attributeauthority/saml', 
                                 params=request, 
                                 headers=header, 
                                 status=200)
        
        print("Response status=%d" % response.status)
        
        samlResponse = self._getSAMLResponse(response.body)

        self.assert_(samlResponse.status.statusCode.value == \
                     StatusCode.INVALID_ATTR_NAME_VALUE_URI)

    def test03InvalidAttributesRequested(self):
        attributeQuery = self._createAttributeQuery()
        
        # Add an unsupported Attribute name
        attribute = Attribute()
        attribute.name = "urn:my:attribute"
        attribute.nameFormat = XMLConstants.XSD_NS+"#"+\
                                    XSStringAttributeValue.TYPE_LOCAL_NAME
        attribute.friendlyName = "myAttribute"
        attributeQuery.attributes.append(attribute)     
        
        request = self._makeRequest(attributeQuery=attributeQuery)
           
        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
       
        response = self.app.post('/attributeauthority/saml', 
                                 params=request, 
                                 headers=header, 
                                 status=200)
        
        print("Response status=%d" % response.status)
        
        samlResponse = self._getSAMLResponse(response.body)

        self.assert_(samlResponse.status.statusCode.value == \
                     StatusCode.INVALID_ATTR_NAME_VALUE_URI)
        
    def test04InvalidIssuer(self):
        request = self._makeRequest(issuer="My Attribute Query Issuer")
        
        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
       
        response = self.app.post('/attributeauthority/saml', 
                                 params=request, 
                                 headers=header, 
                                 status=200)
        
        print("Response status=%d" % response.status)
        
        samlResponse = self._getSAMLResponse(response.body)

        self.assert_(samlResponse.status.statusCode.value == \
                     StatusCode.REQUEST_DENIED_URI)

    def test05UnknownPrincipal(self):
        request = self._makeRequest(subject="Joe.Bloggs")
        
        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
        
        response = self.app.post('/attributeauthority/saml', 
                                 params=request, 
                                 headers=header, 
                                 status=200)
        
        print("Response status=%d" % response.status)
        
        samlResponse = self._getSAMLResponse(response.body)

        self.assert_(samlResponse.status.statusCode.value == \
                     StatusCode.UNKNOWN_PRINCIPAL_URI)
           
if __name__ == "__main__":
    unittest.main()