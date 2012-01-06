"""Tests for AttributeSelector in policies with resource content XML in the
requests
"""
__author__ = "R B Wilkinson"
__date__ = "06/01/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import logging
import unittest

try: # python 2.5
    from xml.etree import cElementTree, ElementTree
except ImportError:
    # if you've installed it yourself it comes this way
    import cElementTree, ElementTree
from ndg.xacml.core.context.resource import Resource as XacmlResource
from ndg.xacml.core.context import XacmlContextBase
from ndg.xacml.parsers.etree.factory import ReaderFactory
from ndg.xacml.core.context.pdp import PDP
from ndg.xacml.core.context.result import Decision
from ndg.xacml.test import XACML_ATTRIBUTESELECTOR1_FILEPATH
from ndg.xacml.test import XACML_ATTRIBUTESELECTOR2_FILEPATH
from ndg.xacml.test.context import XacmlContextBaseTestCase
from ndg.xacml.utils.etree import QName
from ndg.xacml.utils.xpath_selector import EtreeXPathSelector

from ndg.xacml.parsers.etree.context import RequestElementTree

logging.basicConfig(level=logging.DEBUG)

class Test(XacmlContextBaseTestCase):
    """Tests use of AttributeSelector in policies with resource content XML in
    the requests.
    """
    NOT_APPLICABLE_RESOURCE_ID = 'https://localhost'
    PUBLIC_RESOURCE_ID = 'http://localhost/resource-only-restricted'

    RESOURCE_CONTENT_VERSION_100 = \
'''<wps:GetCapabilities xmlns:ows="http://www.opengis.net/ows/1.1"
                     xmlns:wps="http://www.opengis.net/wps/1.0.0"
                     xmlns:xlink="http://www.w3.org/1999/xlink"
                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                     xsi:schemaLocation="http://www.opengis.net/wps/1.0.0/wpsGetCapabilities_request.xsd"
                     language="en-CA" service="WPS">
    <wps:AcceptVersions>
        <ows:Version>1.0.0</ows:Version>
    </wps:AcceptVersions>
</wps:GetCapabilities>
'''
    RESOURCE_CONTENT_VERSION_200 = \
'''<wps:GetCapabilities xmlns:ows="http://www.opengis.net/ows/1.1"
                     xmlns:wps="http://www.opengis.net/wps/1.0.0"
                     xmlns:xlink="http://www.w3.org/1999/xlink"
                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                     xsi:schemaLocation="http://www.opengis.net/wps/1.0.0/wpsGetCapabilities_request.xsd"
                     language="en-CA" service="WPS">
    <wps:AcceptVersions>
        <ows:Version>2.0.0</ows:Version>
    </wps:AcceptVersions>
</wps:GetCapabilities>
'''
    RESOURCE_CONTENT_NO_VERSION = \
'''<wps:GetCapabilities xmlns:ows="http://www.opengis.net/ows/1.1"
                     xmlns:wps="http://www.opengis.net/wps/1.0.0"
                     xmlns:xlink="http://www.w3.org/1999/xlink"
                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                     xsi:schemaLocation="http://www.opengis.net/wps/1.0.0/wpsGetCapabilities_request.xsd"
                     language="en-CA" service="WPS">
</wps:GetCapabilities>
'''
    RESOURCE_CONTENT_EXECUTE = \
'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<wps:Execute service="WPS" version="1.0.0"
             xmlns:wps="http://www.opengis.net/wps/1.0.0"
             xmlns:ows="http://www.opengis.net/ows/1.1"
             xmlns:xlink="http://www.w3.org/1999/xlink"
             xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
             xsi:schemaLocation="http://www.opengis.net/wps/1.0.0/wpsExecute_request.xsd">
    <ows:Identifier>Buffer</ows:Identifier>
    <wps:DataInputs>
        <wps:Input>
            <ows:Identifier>InputPolygon</ows:Identifier>
            <ows:Title>Playground area</ows:Title>
            <wps:Reference xlink:href="http://foo.bar/some_WFS_request.xml"/>
        </wps:Input>
        <wps:Input>
            <ows:Identifier>BufferDistance</ows:Identifier>
            <ows:Title>Distance which people will walk to get to a playground.</ows:Title>
            <wps:Data>
                <wps:LiteralData>400</wps:LiteralData>
            </wps:Data>
        </wps:Input>
    </wps:DataInputs>
    <wps:ResponseForm>
        <wps:RawDataOutput>
            <ows:Identifier>BufferedPolygon</ows:Identifier>
        </wps:RawDataOutput>
    </wps:ResponseForm>
</wps:Execute>
'''

    def _make_resource_content_element(self, resourceContent):
        resourceContentsElem = ElementTree.XML(resourceContent)
        ElementTree._namespace_map[XacmlContextBase.XACML_2_0_CONTEXT_NS
                            ] = XacmlContextBase.XACML_2_0_CONTEXT_NS_PREFIX
        tag = str(QName(XacmlContextBase.XACML_2_0_CONTEXT_NS,
                        XacmlResource.RESOURCE_CONTENT_ELEMENT_LOCAL_NAME))
        resourceContent = ElementTree.Element(tag)
        resourceContent.append(resourceContentsElem)
        return resourceContent


    def test01NotApplicable(self):
        self.pdp = PDP.fromPolicySource(XACML_ATTRIBUTESELECTOR1_FILEPATH,
                                        ReaderFactory)
        resourceContent = self._make_resource_content_element(
                                    self.__class__.RESOURCE_CONTENT_VERSION_100)
        request = self._createRequestCtx(
                                    self.__class__.NOT_APPLICABLE_RESOURCE_ID,
                                    resourceContent=resourceContent)
        request.elem = RequestElementTree.toXML(request)
        request.attributeSelector = EtreeXPathSelector(request.elem)
        response = self.pdp.evaluate(request)
        self.failIf(response is None, "Null response")
        for result in response.results:
            self.failIf(result.decision != Decision.NOT_APPLICABLE,
                        "Expecting not applicable decision")

    def test02Permit(self):
        self.pdp = PDP.fromPolicySource(XACML_ATTRIBUTESELECTOR1_FILEPATH,
                                        ReaderFactory)
        resourceContent = self._make_resource_content_element(
                                    self.__class__.RESOURCE_CONTENT_VERSION_100)
        request = self._createRequestCtx(
                                    self.__class__.PUBLIC_RESOURCE_ID,
                                    resourceContent=resourceContent)
        request.elem = RequestElementTree.toXML(request)
        request.attributeSelector = EtreeXPathSelector(request.elem)
        response = self.pdp.evaluate(request)
        self.failIf(response is None, "Null response")
        for result in response.results:
            self.failIf(result.decision != Decision.PERMIT,
                        "Expecting permit decision")

    def test03Deny(self):
        self.pdp = PDP.fromPolicySource(XACML_ATTRIBUTESELECTOR1_FILEPATH,
                                        ReaderFactory)
        resourceContent = self._make_resource_content_element(
                                    self.__class__.RESOURCE_CONTENT_VERSION_200)
        request = self._createRequestCtx(
                                    self.__class__.PUBLIC_RESOURCE_ID,
                                    resourceContent=resourceContent)
        request.elem = RequestElementTree.toXML(request)
        request.attributeSelector = EtreeXPathSelector(request.elem)
        response = self.pdp.evaluate(request)
        self.failIf(response is None, "Null response")
        for result in response.results:
            self.failIf(result.decision != Decision.DENY,
                        "Expecting deny decision")

    def test04Indeterminate(self):
        '''This should result in an indeterminate decision because the policy
        includes an AttributeSelector with MustBePresent="true", whereas the
        request context path is not found in the request XML.
        '''
        self.pdp = PDP.fromPolicySource(XACML_ATTRIBUTESELECTOR1_FILEPATH,
                                        ReaderFactory)
        resourceContent = self._make_resource_content_element(
                                    self.__class__.RESOURCE_CONTENT_NO_VERSION)
        request = self._createRequestCtx(
                                    self.__class__.PUBLIC_RESOURCE_ID,
                                    resourceContent=resourceContent)
        request.elem = RequestElementTree.toXML(request)
        request.attributeSelector = EtreeXPathSelector(request.elem)
        response = self.pdp.evaluate(request)
        self.failIf(response is None, "Null response")
        for result in response.results:
            self.failIf(result.decision != Decision.INDETERMINATE,
                        "Expecting indeterminate decision")

    def test05ExecutePermit(self):
        self.pdp = PDP.fromPolicySource(XACML_ATTRIBUTESELECTOR2_FILEPATH,
                                        ReaderFactory)
        resourceContent = self._make_resource_content_element(
                                    self.__class__.RESOURCE_CONTENT_EXECUTE)
        request = self._createRequestCtx(
                                    self.__class__.PUBLIC_RESOURCE_ID,
                                    resourceContent=resourceContent)
        request.elem = RequestElementTree.toXML(request)
        request.attributeSelector = EtreeXPathSelector(request.elem)
        response = self.pdp.evaluate(request)
        self.failIf(response is None, "Null response")
        for result in response.results:
            self.failIf(result.decision != Decision.PERMIT,
                        "Expecting permit decision")


if __name__ == "__main__":
    unittest.main()
