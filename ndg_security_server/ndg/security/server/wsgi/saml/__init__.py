"""WSGI SAML Module for SAML 2.0 Assertion Query/Request Profile implementation

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "17/08/2009"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
__license__ = "BSD - see LICENSE file in top-levle directory"
import logging
log = logging.getLogger(__name__)
from cStringIO import StringIO
from uuid import uuid4
from datetime import datetime
from xml.etree import ElementTree

from saml.saml2.core import (Response, Assertion, Attribute, AttributeValue, 
                             AttributeStatement, SAMLVersion, Subject, NameID, 
                             Issuer, AttributeQuery, XSStringAttributeValue, 
                             Conditions, Status, StatusCode)
    
from saml.common.xml import SAMLConstants
from saml.xml import UnknownAttrProfile
from saml.xml.etree import (AssertionElementTree, AttributeQueryElementTree, 
                            ResponseElementTree, QName)

from ndg.security.common.saml_utils.esg import XSGroupRoleAttributeValue
from ndg.security.common.saml_utils.esg.xml.etree import (
                                        XSGroupRoleAttributeValueElementTree)
from ndg.security.common.soap.etree import SOAPEnvelope
from ndg.security.common.utils.etree import prettyPrint
from ndg.security.server.wsgi import NDGSecurityPathFilter
from ndg.security.server.wsgi.soap import SOAPMiddleware


class SOAPAttributeInterfaceMiddlewareError(Exception):
    """Base class for WSGI SAML 2.0 SOAP Attribute Interface Errors"""


class SOAPAttributeInterfaceMiddlewareConfigError(Exception):
    """WSGI SAML 2.0 SOAP Attribute Interface Configuration problem"""

  
class SOAPAttributeInterfaceMiddleware(SOAPMiddleware, NDGSecurityPathFilter):
    """Implementation of SAML 2.0 SOAP Binding for Assertion Query/Request
    Profile
    
    @type PATH_OPTNAME: basestring
    @cvar PATH_OPTNAME: name of app_conf option for specifying a path or paths
    that this middleware will intercept and process
    @type QUERY_INTERFACE_KEYNAME_OPTNAME: basestring
    @cvar QUERY_INTERFACE_KEYNAME_OPTNAME: app_conf option name for key name
    used to reference the SAML query interface in environ
    @type DEFAULT_QUERY_INTERFACE_KEYNAME: basestring
    @param DEFAULT_QUERY_INTERFACE_KEYNAME: default key name for referencing
    SAML query interface in environ
    """
    log = logging.getLogger('SOAPAttributeInterfaceMiddleware')
    PATH_OPTNAME = "pathMatchList"
    QUERY_INTERFACE_KEYNAME_OPTNAME = "queryInterfaceKeyName"
    DEFAULT_QUERY_INTERFACE_KEYNAME = ("ndg.security.server.wsgi.saml."
                            "SOAPAttributeInterfaceMiddleware.queryInterface")
    
    def __init__(self, app):
        '''@type app: callable following WSGI interface
        @param app: next middleware application in the chain 
        '''     
        NDGSecurityPathFilter.__init__(self, app, None)
        
        self._app = app
                 
    def initialise(self, global_conf, prefix='', **app_conf):
        '''
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        '''
        self.__queryInterfaceKeyName = None
        
        self.pathMatchList = app_conf.get(
            prefix + SOAPAttributeInterfaceMiddleware.PATH_OPTNAME, ['/'])
                   
        self.queryInterfaceKeyName = app_conf.get(prefix + \
            SOAPAttributeInterfaceMiddleware.QUERY_INTERFACE_KEYNAME_OPTNAME,
            prefix + \
            SOAPAttributeInterfaceMiddleware.DEFAULT_QUERY_INTERFACE_KEYNAME)
        
    @classmethod
    def filter_app_factory(cls, app, global_conf, **app_conf):
        """Set-up using a Paste app factory pattern.  Set this method to avoid
        possible conflicts from multiple inheritance
        
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        app = cls(app)
        app.initialise(global_conf, **app_conf)
        
        return app
    
    def _getQueryInterfaceKeyName(self):
        return self.__queryInterfaceKeyName

    def _setQueryInterfaceKeyName(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "queryInterfaceKeyName"'
                            ' got %r' % value)
            
        self.__queryInterfaceKeyName = value

    queryInterfaceKeyName = property(fget=_getQueryInterfaceKeyName, 
                                     fset=_setQueryInterfaceKeyName, 
                                     doc="environ keyname for Attribute Query "
                                         "interface")

    def _getIssuerName(self):
        return self.__issuerName

    def _setIssuerName(self, value):
        self.__issuerName = value

    issuerName = property(fget=_getIssuerName, 
                          fset=_setIssuerName, 
                          doc="Name of assertion issuing authority")
    
    @NDGSecurityPathFilter.initCall
    def __call__(self, environ, start_response):
        """Check for and parse a SOAP SAML Attribute Query and return a
        SAML Response
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        """
        
        # Ignore non-matching path
        if not self.pathMatch:
            return self._app(environ, start_response)
          
        # Ignore non-POST requests
        if environ.get('REQUEST_METHOD') != 'POST':
            return self._app(environ, start_response)
        
        soapRequestStream = environ.get('wsgi.input')
        if soapRequestStream is None:
            raise SOAPAttributeInterfaceMiddlewareError('No "wsgi.input" in '
                                                        'environ')
        
        # TODO: allow for chunked data
        contentLength = environ.get('CONTENT_LENGTH')
        if contentLength is None:
            raise SOAPAttributeInterfaceMiddlewareError('No "CONTENT_LENGTH" '
                                                        'in environ')

        contentLength = int(contentLength)        
        soapRequestTxt = soapRequestStream.read(contentLength)
        
        # Parse into a SOAP envelope object
        soapRequest = SOAPEnvelope()
        soapRequest.parse(StringIO(soapRequestTxt))
        
        # Filter based on SOAP Body content - expecting an AttributeQuery
        # element
        if not SOAPAttributeInterfaceMiddleware.isAttributeQuery(
                                                            soapRequest.body):
            # Reset wsgi.input for middleware and app downstream
            environ['wsgi.input'] = StringIO(soapRequestTxt)
            return self._app(environ, start_response)
        
        log.debug("SOAPAttributeInterfaceMiddleware.__call__: received SAML "
                  "SOAP AttributeQuery ...")
       
        attributeQueryElem = soapRequest.body.elem[0]
        
        try:
            attributeQuery = AttributeQueryElementTree.fromXML(
                                                            attributeQueryElem)
        except UnknownAttrProfile, e:
            log.exception("Parsing incoming attribute query: " % e)
            samlResponse = self._makeErrorResponse(
                                        StatusCode.UNKNOWN_ATTR_PROFILE_URI)
        else:   
            # Check for Query Interface in environ
            queryInterface = environ.get(self.queryInterfaceKeyName)
            if queryInterface is None:
                raise SOAPAttributeInterfaceMiddlewareConfigError(
                                'No query interface "%s" key found in environ'%
                                self.queryInterfaceKeyName)
            
            # Call query interface        
            samlResponse = queryInterface(attributeQuery)
        
        # Add mapping for ESG Group/Role Attribute Value to enable ElementTree
        # Attribute Value factory to render the XML output
        toXMLTypeMap = {
            XSGroupRoleAttributeValue: XSGroupRoleAttributeValueElementTree
        }
        
        # Convert to ElementTree representation to enable attachment to SOAP
        # response body
        samlResponseElem = ResponseElementTree.toXML(samlResponse,
                                            customToXMLTypeMap=toXMLTypeMap)
        xml = ElementTree.tostring(samlResponseElem)
        
        # Create SOAP response and attach the SAML Response payload
        soapResponse = SOAPEnvelope()
        soapResponse.create()
        soapResponse.body.elem.append(samlResponseElem)
        
        response = soapResponse.serialize()
        
        start_response("200 OK",
                       [('Content-length', str(len(response))),
                        ('Content-type', 'text/xml')])
        return [response]
    
    @classmethod
    def isAttributeQuery(cls, soapBody):
        """Check for AttributeQuery in the SOAP Body"""
        
        if len(soapBody.elem) != 1:
            # TODO: Change to a SOAP Fault?
            raise SOAPAttributeInterfaceMiddlewareError("Expecting single "
                                                        "child element in the "
                                                        "request SOAP "
                                                        "Envelope body")
            
        inputQName = QName(soapBody.elem[0].tag)    
        attributeQueryQName = QName.fromGeneric(
                                        AttributeQuery.DEFAULT_ELEMENT_NAME)
        return inputQName == attributeQueryQName

    def _makeErrorResponse(self, code):
        """Convenience method for making a basic response following an error
        """
        samlResponse = Response()
        
        samlResponse.issueInstant = datetime.utcnow()            
        samlResponse.id = str(uuid4())
        
        # Initialise to success status but reset on error
        samlResponse.status = Status()
        samlResponse.status.statusCode = StatusCode()
        samlResponse.status.statusCode.value = code
        
        return samlResponse
