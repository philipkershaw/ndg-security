"""MSI (Medium Sized Initiative aka NDG3) authorisation unit test module

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "18/11/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
from os import path
from ndg.security.test.unit import BaseTestCase
from ndg.security.common.authz.msi import (Policy, PDP, PIPBase, Subject,
                                           Request, Resource, Response,
                                           PIPAttributeQuery,
                                           PIPAttributeResponse)


class MsiBaseTestCase(BaseTestCase):
    """Base class for passing common class variables between unit test classes
    in this module"""
    THIS_DIR = path.dirname(__file__)
    POLICY_1_1_FILENAME = 'policy-1.1.xml'
    POLICY_1_1_FILEPATH = path.join(THIS_DIR, POLICY_1_1_FILENAME)
    
    
class PolicyTestCase(MsiBaseTestCase):
    """Unit tests for the MSI Policy"""
    POLICY_1_0_FILENAME = 'policy-1.0.xml'
    POLICY_1_0_FILEPATH = path.join(MsiBaseTestCase.THIS_DIR, 
                                    POLICY_1_0_FILENAME)
    ATTRIBUTE_AUTHORITY_URI = 'http://localhost:7443/AttributeAuthority'
    
    def test01ParseVersion1_0PolicyFile(self):
        policy = Policy.Parse(PolicyTestCase.POLICY_1_0_FILEPATH)
        
        assert(policy)
        assert(len(policy.targets) > 0)
        
        for target in policy.targets:
            assert(len(target.attributes) > 0)
            
            for attribute in target.attributes:
                assert(attribute.name)
                assert(attribute.attributeAuthorityURI == \
                       PolicyTestCase.ATTRIBUTE_AUTHORITY_URI)
        
    def test02ParseVersion1_1PolicyFile(self):
        policy = Policy.Parse(PolicyTestCase.POLICY_1_1_FILEPATH)
        
        assert(policy)
        assert(len(policy.targets) > 0)
        
        for target in policy.targets:
            assert(len(target.attributes) > 0)
            
            for attribute in target.attributes:
                assert(attribute.name)
                assert(attribute.attributeAuthorityURI)


class PIPPlaceholder(PIPBase):
    """Policy Information Point for Testing the PDP"""
    def __init__(self):
        pass
    
    def attributeQuery(self, attributeQuery):
        subject = attributeQuery[PIPAttributeQuery.SUBJECT_NS]
        username = subject[Subject.USERID_NS]
        
        attributeResponse = PIPAttributeResponse()
        
        if username == BaseTestCase.OPENID_URI:
            attributeResponse[Subject.ROLES_NS] = BaseTestCase.ATTRIBUTE_VALUES
            
        return attributeResponse

    
class PDPTestCase(MsiBaseTestCase):
    """Unit tests for the Policy Decision Point"""
    PERMITTED_RESOURCE_URI = '/test_securedURI'
    DENIED_RESOURCE_URI = '/test_accessDeniedToSecuredURI'
    
    def setUp(self):
        pip = PIPPlaceholder()
        policy = Policy.Parse(PDPTestCase.POLICY_1_1_FILEPATH)
        self.pdp = PDP(policy, pip)
        
        # Make a request object to pass to the PDP
        self.request = Request()
        self.request.subject[Subject.USERID_NS] = PDPTestCase.OPENID_URI
    
    def test01AccessPermitted(self):
        self.request.resource[Resource.URI_NS
                              ] = PDPTestCase.PERMITTED_RESOURCE_URI
        response = self.pdp.evaluate(self.request)
        
        self.assert_(response.status == Response.DECISION_PERMIT)

    def test02AccessDenied(self):
        self.request.resource[Resource.URI_NS] = PDPTestCase.DENIED_RESOURCE_URI      
        response = self.pdp.evaluate(self.request)
        
        self.assert_(response.status == Response.DECISION_DENY)

        
if __name__ == "__main__":
    import unittest
    unittest.main()