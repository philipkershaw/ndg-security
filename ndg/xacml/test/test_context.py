#!/usr/bin/env python
"""NDG XACML Context unit test package 

NERC DataGrid
"""
__author__ = "P J Kershaw"
__date__ = "26/03/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import unittest
from os import path
import logging
logging.basicConfig(level=logging.DEBUG)

from ndg.xacml.test import XACML_NDGTEST1_FILEPATH
from ndg.xacml.parsers.etree.factory import ReaderFactory
from ndg.xacml.core.context.pdpinterface import PDPInterface
from ndg.xacml.core.context.pdp import PDP
from ndg.xacml.core.context.handler import CtxHandlerInterface
from ndg.xacml.core.attribute import Attribute
from ndg.xacml.core.attributevalue import AttributeValueClassFactory
from ndg.xacml.core.context.request import Request
from ndg.xacml.core.context.response import Response
from ndg.xacml.core.context.result import Result, Decision
from ndg.xacml.core.context.subject import Subject
from ndg.xacml.core.context.resource import Resource
from ndg.xacml.core.context.action import Action

                
class TestContextHandler(CtxHandlerInterface):
    """Test implementation of Context Handler"""
    
    def __init__(self):
        """Add an attribute to hold a reference to a policy information point"""
        
        super(TestContextHandler, self).__init__()
        self.pip = None        
        
    def handlePEPRequest(self, myRequest):
        """Handle request from Policy Enforcement Point
        
        @param pepRequest: request from PEP, derived class determines its type
        e.g. SAML AuthzDecisionQuery
        @type myRequest: type
        @return: PEP response - derived class determines type
        @rtype: None
        """
        
        # Convert myRequest to XACML context request - var assignment here is 
        # representative of this process rather than actually doing anything.
        request = myRequest
        
        if self.pdp is None:
            raise TypeError('No "pdp" attribute set')
        
        response = self.pdp.evaluate(request)
        
        # Convert XACML context response to domain specific request
        myResponse = response
        
        return myResponse


class XACMLContextTestCase(unittest.TestCase):
    """Test PDP, PAP, PIP and Context handler"""
    
    def _createRequestCtx(self):
        request = Request()
        subject = Subject()
        
        attributeValueFactory = AttributeValueClassFactory()
        
        openidSubjectAttribute = Attribute()
        roleAttribute = Attribute()
        
        openidSubjectAttribute.attributeId = "urn:esg:openid"
        AnyUriAttributeValue = attributeValueFactory(
                                    'http://www.w3.org/2001/XMLSchema#anyURI')
        openidSubjectAttribute.dataType = AnyUriAttributeValue.IDENTIFIER
        
        openidSubjectAttribute.attributeValues.append(AnyUriAttributeValue())
        openidSubjectAttribute.attributeValues[-1].value = \
                                    'https://my.name.somewhere.ac.uk'
        
        subject.attributes.append(openidSubjectAttribute)

        StringAttributeValue = attributeValueFactory(
                                    'http://www.w3.org/2001/XMLSchema#string')

        roleAttribute.attributeId = "urn:ndg:security:authz:1.0:attr"
        roleAttribute.dataType = StringAttributeValue.IDENTIFIER
        
        roleAttribute.attributeValues.append(StringAttributeValue())
        roleAttribute.attributeValues[-1].value = 'staff' 
        
        subject.attributes.append(roleAttribute)
                                  
        request.subjects.append(subject)
        
        resource = Resource()
        resourceAttribute = Attribute()
        resource.attributes.append(resourceAttribute)
        
        resourceAttribute.attributeId = \
                            "urn:oasis:names:tc:xacml:1.0:resource:resource-id"
                            
        resourceAttribute.dataType = AnyUriAttributeValue.IDENTIFIER
        resourceAttribute.attributeValues.append(AnyUriAttributeValue())
        resourceAttribute.attributeValues[-1].value = \
                                            'http://localhost/test_securedURI'

        request.resources.append(resource)
        
        request.action = Action()
        actionAttribute = Attribute()
        request.action.attributes.append(actionAttribute)
        
        actionAttribute.attributeId = \
                                "urn:oasis:names:tc:xacml:1.0:action:action-id"
        actionAttribute.dataType = StringAttributeValue.IDENTIFIER
        actionAttribute.attributeValues.append(StringAttributeValue())
        actionAttribute.attributeValues[-1].value = 'read'
        
        return request
    
    def test01CreateRequest(self):
        requestCtx = self._createRequestCtx()
        self.assert_(requestCtx)
        
    def test02CreateResponse(self):
        response = Response()
        result = Result()
        response.results.append(result)
        result.decision = Decision()
        result.decision.value = Decision.NOT_APPLICABLE
        
    def test03AbstractCtxHandler(self):
        self.assertRaises(TypeError, CtxHandlerInterface, 
                          "Context handler is an abstract base class")
        
    def test04CreateCtxHandler(self):
        ctxHandler = TestContextHandler()
        
    def test05PDPInterface(self):
        self.assertRaises(TypeError, PDPInterface)
        
    def test06CreatePDP(self):
        pdp = PDP()
        self.assert_(pdp)
        
    def _createPDPfromPolicy(self):
        pdp = PDP.fromPolicySource(XACML_NDGTEST1_FILEPATH, ReaderFactory)
        return pdp
        
    def test07CreatePDPfromPolicy(self):
        pdp = self._createPDPfromPolicy()
        self.assert_(pdp)
        
    def test08EvaluatePDP(self):
        request = self._createRequestCtx()
        pdp = self._createPDPfromPolicy()
        response = pdp.evaluate(request)
        self.assert_(response)

        
if __name__ == "__main__":
    unittest.main()