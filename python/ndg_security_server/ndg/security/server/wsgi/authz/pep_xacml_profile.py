'''NDG Security Policy Enforcement Point Module

__author__ = "P J Kershaw"
__date__ = "11/07/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: pep.py 7897 2011-04-27 11:02:23Z pjkersha $'
'''
import logging
log = logging.getLogger(__name__)

import httplib
import webob

try: # python 2.5
    from xml.etree import cElementTree, ElementTree
except ImportError:
    # if you've installed it yourself it comes this way
    import cElementTree, ElementTree

from ndg.saml.saml2.core import DecisionType
from ndg.saml.saml2.binding.soap.client.xacmlauthzdecisionquery import \
                                        XACMLAuthzDecisionQuerySslSOAPBinding
from ndg.saml.saml2.xacml_profile import XACMLAuthzDecisionStatement
from ndg.saml.xml.etree import QName
import ndg.saml.xml.etree_xacml_profile as etree_xacml_profile

from ndg.xacml.core import Identifiers as XacmlIdentifiers
from ndg.xacml.core.attribute import Attribute as XacmlAttribute
from ndg.xacml.core.attributevalue import (
    AttributeValueClassFactory as XacmlAttributeValueClassFactory, 
    AttributeValue as XacmlAttributeValue)
    
from ndg.security.server.wsgi.authz.pep import SamlPepFilterConfigError
from ndg.security.server.wsgi.authz.pep import SamlPepFilterBase

from ndg.xacml.core.context.action import Action as XacmlAction
from ndg.xacml.core.context.environment import Environment as XacmlEnvironment
from ndg.xacml.core.context.request import Request as XacmlRequest
from ndg.xacml.core.context.resource import Resource as XacmlResource
from ndg.xacml.core.context.result import Decision as XacmlDecision
from ndg.xacml.core.context.subject import Subject as XacmlSubject
from ndg.xacml.core.context import XacmlContextBase


class XacmlSamlPepFilter(SamlPepFilterBase):
    '''Policy Enforcement Point for ESG with SAML based Interface
    
    @requires: ndg.security.server.wsgi.session.SessionHandlerMiddleware 
    instance upstream in the WSGI stack.
    
    @cvar AUTHZ_DECISION_QUERY_PARAMS_PREFIX: prefix for SAML authorisation
    decision query options in config file
    @type AUTHZ_DECISION_QUERY_PARAMS_PREFIX: string
    
    @cvar PARAM_NAMES: list of config option names
    @type PARAM_NAMES: tuple
    
    @ivar __client: SAML authorisation decision query client 
    @type __client: ndg.saml.saml2.binding.soap.client.authzdecisionquery.AuthzDecisionQuerySslSOAPBinding
    '''
    SUBJECT_ID_FORMAT_PARAM_NAME = 'subjectIdFormat'

    PARAM_NAMES = [
        SUBJECT_ID_FORMAT_PARAM_NAME
    ]

    __slots__ = tuple(('__' + '$__'.join(PARAM_NAMES)).split('$'))

    def _getSubjectIdFormat(self):
        return self.__subjectIdFormat

    def _setSubjectIdFormat(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "subjectIdFormat" '
                            'attribute; got %r' % type(value))
        self.__subjectIdFormat = value

    subjectIdFormat = property(_getSubjectIdFormat, _setSubjectIdFormat, 
                          doc="Subject format ID to use in XACML subject "
                          "attribute")

    def initialise(self, prefix='', **kw):
        '''Initialise object from keyword settings
        
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type kw: dict        
        @param kw: configuration settings
        dictionary
        @raise SamlPepFilterConfigError: missing option setting(s)
        '''
        self.client = XACMLAuthzDecisionQuerySslSOAPBinding()
        # Additional parameter required for XAML profile:
        for name in self.__class__.PARAM_NAMES:
            paramName = prefix + name
            value = kw.get(paramName)
            
            if value is not None:
                setattr(self, name, value)
            else:
                raise SamlPepFilterConfigError(
                    'Missing option %r for XACML profile' % paramName)

        # Include XACML profile elements for element tree processing.
        etree_xacml_profile.setElementTreeMap()

        super(XacmlSamlPepFilter, self).initialise(prefix, **kw)

    def enforce(self, environ, start_response):
        """Get access control decision from PDP(s) and enforce the decision
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: response
        """
        request = webob.Request(environ)
        requestURI = request.url
        
        # Apply local PDP if set
        if not self.isApplicableRequest(requestURI):
            # The local PDP has returned a decision that the requested URI is
            # not applicable and so the authorisation service need not be 
            # invoked.  This step is an efficiency measure to avoid multiple
            # callouts to the authorisation service for resources which 
            # obviously don't need any restrictions 
            return self._app(environ, start_response)

        # Check for cached decision
        if self.cacheDecisions:
            assertions = self._retrieveCachedAssertions(requestURI)
        else:
            assertions = None  

        subjectID = request.remote_user or ''

        noCachedAssertion = assertions is None or len(assertions) == 0
        if noCachedAssertion:
            xacmlContextRequest = self._make_xacml_context_request(request,
                                                                   subjectID,
                                                        self.subjectIdFormat)
            self.client.query.xacmlContextRequest = xacmlContextRequest
            samlAuthzResponse = self.client.send(uri=self.authzServiceURI)
            assertions = samlAuthzResponse.assertions
            
            # Record the result in the user's session to enable later 
            # interrogation by any result handler Middleware
            self.saveResultCtx(self.client.query, samlAuthzResponse)
        
        
        # Set HTTP 403 Forbidden response if any of the decisions returned are
        # deny or indeterminate status
        failDecisions = (DecisionType.DENY, DecisionType.INDETERMINATE)
        ### TODO What should be done with NOT_APPLICABLE decision?
        xacmlFailDecisions = [XacmlDecision.DENY, XacmlDecision.INDETERMINATE,
                              XacmlDecision.NOT_APPLICABLE]
        
        # Review decision statement(s) in assertions and enforce the decision
        assertion = None
        invalid_response = False
        for assertion in assertions:
            for statement in assertion.statements:
                if not isinstance(statement, XACMLAuthzDecisionStatement):
                    # Unexpected statement type
                    invalid_response = True
                results = statement.xacmlContextResponse.results
                # Should be one result as only supplying one resource in the
                # request.
                if len(results) != 1:
                    invalid_response = True

                if results[0].decision in xacmlFailDecisions:
                    response = webob.Response()
                    
                    if not subjectID:
                        # Access failed and the user is not logged in
                        response.status = httplib.UNAUTHORIZED
                    else:
                        # The user is logged in but not authorised
                        response.status = httplib.FORBIDDEN

                    response.body = 'Access denied to %r for user %r' % (
                                                                     requestURI,
                                                                     subjectID)
                    response.content_type = 'text/plain'
                    log.info(response.body)
                    return response(environ, start_response)

            ### TODO Is a non-XACML-profile response permitted?
            for authzDecisionStatement in assertion.authzDecisionStatements:
                if authzDecisionStatement.decision.value in failDecisions:
                    response = webob.Response()
                    
                    if not subjectID:
                        # Access failed and the user is not logged in
                        response.status = httplib.UNAUTHORIZED
                    else:
                        # The user is logged in but not authorised
                        response.status = httplib.FORBIDDEN
                        
                    response.body = 'Access denied to %r for user %r' % (
                                                     requestURI,
                                                     subjectID)
                    response.content_type = 'text/plain'
                    log.info(response.body)
                    return response(environ, start_response)

            if invalid_response:
                response = webob.Response()
                response.status = httplib.INTERNAL_SERVER_ERROR
                response.body = 'Unexpected response from security service'
                response.content_type = 'text/plain'
                log.info(response.body)
                return response(environ, start_response)

        if assertion is None:
            log.error("No assertions set in authorisation decision response "
                      "from %r", self.authzServiceURI)
            
            response = webob.Response()
            response.status = httplib.FORBIDDEN
            response.body = ('An error occurred retrieving an access decision '
                             'for %r for user %r' % (
                                             requestURI,
                                             subjectID))
            response.content_type = 'text/plain'
            log.info(response.body)
            return response(environ, start_response)     
               
        # Cache assertion if flag is set and it's one that's been freshly 
        # obtained from an authorisation decision query rather than one 
        # retrieved from the cache
        if self.cacheDecisions and noCachedAssertion:
            self._cacheAssertions(request.url, [assertion])
            
        # If got through to here then all is well, call next WSGI middleware/app
        return self._app(environ, start_response)

    def _make_xacml_context_request(self, httpRequest, subjectID,
                                    subjectIdFormat):
        """Create a XACML Request. Include post data as resource content if the
        HTTP method is POST.
        @type httpRequest: webob.Request
        @param httpRequest: HTTP request object
        @type subjectID: str
        @param subjectID: subject ID
        @type subjectIdFormat: str
        @param subjectIdFormat: subject ID format
        """
        resourceURI = httpRequest.url
        if httpRequest.method == 'GET':
            ### TODO need actions
            return self._createXacmlProfileRequestCtx(subjectIdFormat,
                                                      subjectID, resourceURI,
                                                      None, [])

        elif httpRequest.method == 'POST':
            rcContentsStr = httpRequest.body_file_seekable.read()
            rcContentsElem = ElementTree.XML(rcContentsStr)
            ElementTree._namespace_map[XacmlContextBase.XACML_2_0_CONTEXT_NS
                                ] = XacmlContextBase.XACML_2_0_CONTEXT_NS_PREFIX
            tag = str(QName(XacmlContextBase.XACML_2_0_CONTEXT_NS,
                            XacmlResource.RESOURCE_CONTENT_ELEMENT_LOCAL_NAME))
            resourceContent = ElementTree.Element(tag)
            resourceContent.append(rcContentsElem)
            resourceContent.set('TestAttribute', 'Test Value')
    
            request = self._createXacmlProfileRequestCtx(subjectIdFormat,
                                                         subjectID, resourceURI,
                                                         resourceContent,
                                                         [])

            return request

    def _createXacmlProfileRequestCtx(self, subjectNameIdFormat, subjectNameId,
                                      resourceUri, resourceContent, actions):
        """Translate SAML authorisation decision query into a XACML request
        context
        @type subjectNameIdFormat: str
        @param subjectNameIdFormat: subject ID format
        @type subjectNameId: str
        @param subjectNameId: subject ID
        @type resourceUri: str
        @param resourceUri: resource URI
        @type resourceContent: ElementTree.Element
        @param resourceContent: data to include as resource content
        @type actions: list of str
        @param actions: action values
        """
        xacmlRequest = XacmlRequest()
        xacmlSubject = XacmlSubject()
        
        xacmlAttributeValueFactory = XacmlAttributeValueClassFactory()
        
        openidSubjectAttribute = XacmlAttribute()
        roleAttribute = XacmlAttribute()
        
        openidSubjectAttribute.attributeId = \
                                subjectNameIdFormat
                                        
        XacmlAnyUriAttributeValue = xacmlAttributeValueFactory(
                                            XacmlAttributeValue.ANY_TYPE_URI)
        
        openidSubjectAttribute.dataType = XacmlAnyUriAttributeValue.IDENTIFIER
        
        openidSubjectAttribute.attributeValues.append(
                                                    XacmlAnyUriAttributeValue())
        openidSubjectAttribute.attributeValues[-1].value = \
                                subjectNameId
        
        xacmlSubject.attributes.append(openidSubjectAttribute)

        XacmlStringAttributeValue = xacmlAttributeValueFactory(
                                            XacmlAttributeValue.STRING_TYPE_URI)
                                  
        xacmlRequest.subjects.append(xacmlSubject)
        
        resource = XacmlResource()
        resourceAttribute = XacmlAttribute()
        resource.attributes.append(resourceAttribute)
        if resourceContent:
            resource.resourceContent = resourceContent
        
        resourceAttribute.attributeId = XacmlIdentifiers.Resource.RESOURCE_ID
                            
        resourceAttribute.dataType = XacmlAnyUriAttributeValue.IDENTIFIER
        resourceAttribute.attributeValues.append(XacmlAnyUriAttributeValue())
        resourceAttribute.attributeValues[-1].value = \
                                                resourceUri

        xacmlRequest.resources.append(resource)
        
        xacmlRequest.action = XacmlAction()
        
        for action in actions:
            xacmlActionAttribute = XacmlAttribute()
            xacmlRequest.action.attributes.append(xacmlActionAttribute)
            
            xacmlActionAttribute.attributeId = XacmlIdentifiers.Action.ACTION_ID
            xacmlActionAttribute.dataType = XacmlStringAttributeValue.IDENTIFIER
            xacmlActionAttribute.attributeValues.append(
                                                    XacmlStringAttributeValue())
            xacmlActionAttribute.attributeValues[-1].value = action.value

        xacmlRequest.environment = XacmlEnvironment()

        return xacmlRequest
