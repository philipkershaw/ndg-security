"""SAML 2.0 bindings module implements SOAP binding for attribute query

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "02/09/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)

import re
from os import path
from datetime import datetime, timedelta
from uuid import uuid4
from ConfigParser import ConfigParser

from M2Crypto.m2urllib2 import HTTPSHandler

from saml.common import SAMLObject
from saml.utils import SAMLDateTime
from saml.saml2.core import (Attribute, AttributeQuery, StatusCode, Response,
                             Issuer, Subject, SAMLVersion, NameID)
from saml.xml.etree import AttributeQueryElementTree, ResponseElementTree

from ndg.security.common.saml_utils.esg import EsgSamlNamespaces
from ndg.security.common.utils import TypedList
from ndg.security.common.utils.configfileparsers import (
                                                    CaseSensitiveConfigParser)
from ndg.security.common.utils.etree import QName   
from ndg.security.common.X509 import X500DN 
from ndg.security.common.soap import SOAPEnvelopeBase
from ndg.security.common.soap.etree import SOAPEnvelope
from ndg.security.common.soap.client import (UrlLib2SOAPClient, 
                                             UrlLib2SOAPRequest)

# Prevent whole module breaking if this is not available - it's only needed for
# AttributeQuerySslSOAPBinding
try:
    from ndg.security.common.utils.m2crypto import SSLContextProxy
    _sslContextProxySupport = True
    
except ImportError:
    _sslContextProxySupport = False



class SOAPBindingError(Exception):
    '''Base exception type for client SAML SOAP Binding for Attribute Query'''


class SOAPBindingInvalidResponse(SOAPBindingError):
    '''Raise if the response is invalid'''
    
    
_isIterable = lambda obj: getattr(obj, '__iter__', False) 
   

class SOAPBinding(object):
    '''Client SAML SOAP Binding'''
    
    isIterable = staticmethod(_isIterable)
    __slots__ = (
        "__client",
        "__requestEnvelopeClass",
        "__serialise",
        "__deserialise"
    )
    
    def __init__(self, 
                 requestEnvelopeClass=SOAPEnvelope,
                 responseEnvelopeClass=SOAPEnvelope,
                 serialise=AttributeQueryElementTree.toXML,
                 deserialise=ResponseElementTree.fromXML,
                 handlers=(HTTPSHandler,)):
        '''Create SAML SOAP Client - Nb. serialisation functions assume 
        AttributeQuery/Response'''
        self.__client = None
        self.serialise = serialise
        self.deserialise = deserialise
        
        self.client = UrlLib2SOAPClient()
        
        # ElementTree based envelope class
        self.requestEnvelopeClass = requestEnvelopeClass
        self.client.responseEnvelopeClass = responseEnvelopeClass

        if not SOAPBinding.isIterable(handlers):
            raise TypeError('Expecting iterable for "handlers" keyword; got %r'
                            % type(handlers))
           
        for handler in handlers:
            self.client.openerDirector.add_handler(handler())

    def _getSerialise(self):
        return self.__serialise

    def _setSerialise(self, value):
        if not callable(value):
            raise TypeError('Expecting callable for "serialise"; got %r' % 
                            value)
        self.__serialise = value

    serialise = property(_getSerialise, _setSerialise, 
                         doc="callable to serialise request into XML type")

    def _getDeserialise(self):
        return self.__deserialise

    def _setDeserialise(self, value):
        if not callable(value):
            raise TypeError('Expecting callable for "deserialise"; got %r' % 
                            value)
        self.__deserialise = value

    deserialise = property(_getDeserialise, 
                           _setDeserialise, 
                           doc="callable to de-serialise response from XML "
                               "type")

    def _getRequestEnvelopeClass(self):
        return self.__requestEnvelopeClass

    def _setRequestEnvelopeClass(self, value):
        if not issubclass(value, SOAPEnvelopeBase):
            raise TypeError('Expecting %r for "requestEnvelopeClass"; got %r'% 
                            (SOAPEnvelopeBase, value))
        
        self.__requestEnvelopeClass = value

    requestEnvelopeClass = property(_getRequestEnvelopeClass, 
                                    _setRequestEnvelopeClass, 
                                    doc="SOAP Envelope Request Class")

    def _getClient(self):
        return self.__client

    def _setClient(self, value):     
        if not isinstance(value, UrlLib2SOAPClient):
            raise TypeError('Expecting %r for "client"; got %r'% 
                            (UrlLib2SOAPClient, type(value)))
        self.__client = value

    client = property(_getClient, _setClient, 
                      doc="SOAP Client object")   

    def send(self, samlObj, uri=None, request=None):
        '''Make an request/query to a remote SAML service
        
        @type samlObj: saml.common.SAMLObject
        @param samlObj: SAML query/request object
        @type uri: basestring 
        @param uri: uri of service.  May be omitted if set from request.url
        @type request: ndg.security.common.soap.UrlLib2SOAPRequest
        @param request: SOAP request object to which query will be attached
        defaults to ndg.security.common.soap.client.UrlLib2SOAPRequest
        '''
        if not isinstance(samlObj, SAMLObject):
            raise TypeError('Expecting %r for input attribute query; got %r'
                            % (SAMLObject, type(samlObj)))
            
        if request is None:
            request = UrlLib2SOAPRequest()            
            request.envelope = self.requestEnvelopeClass()
            request.envelope.create()
            
        if uri is not None:
            request.url = uri
        
        samlElem = self.serialise(samlObj)

        # Attach query to SOAP body
        request.envelope.body.elem.append(samlElem)
            
        response = self.client.send(request)
        
        if len(response.envelope.body.elem) != 1:
            raise SOAPBindingInvalidResponse("Expecting single child element "
                                             "is SOAP body")
            
        if QName.getLocalPart(response.envelope.body.elem[0].tag)!='Response':
            raise SOAPBindingInvalidResponse('Expecting "Response" element in '
                                             'SOAP body')
            
        response = self.deserialise(response.envelope.body.elem[0])
        
        return response
        
    def __getstate__(self):
        '''Enable pickling for use with beaker.session'''
        _dict = {}
        for attrName in SOAPBinding.__slots__:
            # Ugly hack to allow for derived classes setting private member
            # variables
            if attrName.startswith('__'):
                attrName = "_SOAPBinding" + attrName
                
            _dict[attrName] = getattr(self, attrName)
            
        return _dict
        
    def __setstate__(self, attrDict):
        '''Specific implementation needed with __slots__'''
        for attr, val in attrDict.items():
            setattr(self, attr, val)
            

class AttributeQueryResponseError(SOAPBindingInvalidResponse):
    """Attribute Authority returned a SAML Response error code"""
    def __init__(self, *arg, **kw):
        SOAPBindingInvalidResponse.__init__(self, *arg, **kw)
        self.__response = None
    
    def _getResponse(self):
        '''Gets the response corresponding to this error
        
        @return the response
        '''
        return self.__response

    def _setResponse(self, value):
        '''Sets the response corresponding to this error.
        
        @param value: the response
        '''
        if not isinstance(value, Response):
            raise TypeError('"response" must be a %r, got %r' % (Response,
                                                                 type(value)))
        self.__response = value
        
    response = property(fget=_getResponse, fset=_setResponse, 
                        doc="SAML Response associated with this exception")


class AttributeQuerySOAPBinding(SOAPBinding): 
    """SAML Attribute Query SOAP Binding
    
    Nb. Assumes X.509 subject type for query issuer
    """
    SUBJECT_ID_OPTNAME = 'subjectID'
    ISSUER_NAME_OPTNAME = 'issuerName'
    CLOCK_SKEW_OPTNAME = 'clockSkew'
    VERIFY_TIME_CONDITIONS_OPTNAME = 'verifyTimeConditions'
    
    CONFIG_FILE_OPTNAMES = (
        SUBJECT_ID_OPTNAME,
        ISSUER_NAME_OPTNAME,                 
        CLOCK_SKEW_OPTNAME, 
        VERIFY_TIME_CONDITIONS_OPTNAME      
    )
    
    QUERY_ATTRIBUTES_ATTRNAME = 'queryAttributes'
    LEN_QUERY_ATTRIBUTES_ATTRNAME = len(QUERY_ATTRIBUTES_ATTRNAME)
    QUERY_ATTRIBUTES_PAT = re.compile(',\s*')
    
    __PRIVATE_ATTR_PREFIX = "__"
    __slots__ = tuple([__PRIVATE_ATTR_PREFIX + i 
                       for i in \
                       CONFIG_FILE_OPTNAMES + (QUERY_ATTRIBUTES_ATTRNAME,)])
    del i
    
    def __init__(self, **kw):
        '''Create SOAP Client for SAML Attribute Query'''
        self.__issuerName = None
        self.__queryAttributes = TypedList(Attribute)
        self.__clockSkew = timedelta(seconds=0.)
        self.__verifyTimeConditions = True
    
        super(AttributeQuerySOAPBinding, self).__init__(**kw)

    @classmethod
    def fromConfig(cls, cfg, **kw):
        '''Alternative constructor makes object from config file settings
        @type cfg: basestring /ConfigParser derived type
        @param cfg: configuration file path or ConfigParser type object
        @rtype: ndg.security.common.credentialWallet.AttributeQuery
        @return: new instance of this class
        '''
        obj = cls()
        obj.parseConfig(cfg, **kw)
        
        return obj

    def parseConfig(self, cfg, prefix='', section='DEFAULT'):
        '''Read config file settings
        @type cfg: basestring /ConfigParser derived type
        @param cfg: configuration file path or ConfigParser type object
        @type prefix: basestring
        @param prefix: prefix for option names e.g. "attributeQuery."
        @type section: baestring
        @param section: configuration file section from which to extract
        parameters.
        '''  
        if isinstance(cfg, basestring):
            cfgFilePath = path.expandvars(cfg)
            _cfg = CaseSensitiveConfigParser()
            _cfg.read(cfgFilePath)
            
        elif isinstance(cfg, ConfigParser):
            _cfg = cfg   
        else:
            raise AttributeError('Expecting basestring or ConfigParser type '
                                 'for "cfg" attribute; got %r type' % type(cfg))
        
        prefixLen = len(prefix)
        for optName, val in _cfg.items(section):
            if prefix:
                # Filter attributes based on prefix
                if optName.startswith(prefix):
                    setattr(self, optName[prefixLen:], val)
            else:
                # No prefix set - attempt to set all attributes   
                setattr(self, optName, val)
            
    def __setattr__(self, name, value):
        """Enable setting of SAML query attribute objects via a comma separated
        string suitable for use reading from an ini file.  
        """
        try:
            super(AttributeQuerySOAPBinding, self).__setattr__(name, value)
            
        except AttributeError:
            if name.startswith(
                        AttributeQuerySOAPBinding.QUERY_ATTRIBUTES_ATTRNAME):
                # Special handler for parsing string format settings
                if not isinstance(value, basestring):
                    raise TypeError('Expecting string format for special '
                                    '%r attribute; got %r instead' %
                                    (name, type(value)))
                    
                pat = AttributeQuerySOAPBinding.QUERY_ATTRIBUTES_PAT
                attribute = Attribute()
                
                (attribute.name, 
                 attribute.friendlyName, 
                 attribute.nameFormat) = pat.split(value)
                 
                self.queryAttributes.append(attribute)
            else:
                raise

    def _getVerifyTimeConditions(self):
        return self.__verifyTimeConditions

    def _setVerifyTimeConditions(self, value):
        if isinstance(value, bool):
            self.__verifyTimeConditions = value
            
        if isinstance(value, basestring):
            self.__verifyTimeConditions = str2Bool(value)
        else:
            raise TypeError('Expecting bool or string type for '
                            '"verifyTimeConditions"; got %r instead' % 
                            type(value))

    verifyTimeConditions = property(_getVerifyTimeConditions, 
                                    _setVerifyTimeConditions, 
                                    doc='Set to True to verify any time '
                                        'Conditions set in the returned '
                                        'response assertions') 
    
    def _getSubjectID(self):
        return self.__subjectID

    def _setSubjectID(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "subjectID"; got %r '
                            'instead' % type(value))
        self.__subjectID = value

    subjectID = property(_getSubjectID, _setSubjectID, 
                         doc="ID to be sent as query subject")  
             
    def _getQueryAttributes(self):
        """Returns a *COPY* of the attributes to avoid overwriting the 
        member variable content
        """
        return self.__queryAttributes

    def _setQueryAttributes(self, value):
        if not isinstance(value, TypedList) and value.elementType != Attribute:
            raise TypeError('Expecting TypedList(Attribute) type for '
                            '"queryAttributes"; got %r instead' % type(value)) 
        
        self.__queryAttributes = value
    
    queryAttributes = property(_getQueryAttributes, 
                               _setQueryAttributes, 
                               doc="List of attributes to query from the "
                                   "Attribute Authority")

    def _getIssuerName(self):
        return self.__issuerName

    def _setIssuerName(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "issuerName"; '
                            'got %r instead' % type(value))
            
        self.__issuerName = value

    issuerName = property(_getIssuerName, _setIssuerName, 
                        doc="Distinguished Name of issuer of SAML Attribute "
                            "Query to Attribute Authority")

    def _getClockSkew(self):
        return self.__clockSkew

    def _setClockSkew(self, value):
        if isinstance(value, (float, int, long)):
            self.__clockSkew = timedelta(seconds=value)
            
        elif isinstance(value, basestring):
            self.__clockSkew = timedelta(seconds=float(value))
        else:
            raise TypeError('Expecting float, int, long or string type for '
                            '"clockSkew"; got %r' % type(value))

    clockSkew = property(fget=_getClockSkew, 
                         fset=_setClockSkew, 
                         doc="Allow a clock skew in seconds for SAML Attribute"
                             " Query issueInstant parameter check")  

    def _createQuery(self):
        """ Create a SAML attribute query"""
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        if self.issuerName is None:
            raise AttributeError('No issuer DN has been set for SAML Attribute '
                                 'Query')
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = self.issuerName
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = EsgSamlNamespaces.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = self.subjectID
                  
        # Add list of attributes to query                      
        for attribute in self.queryAttributes:
            attributeQuery.attributes.append(attribute)
            
        return attributeQuery
    
    def _verifyTimeConditions(self, response):
        """Verify time conditions set in a response
        @param response: SAML Response returned from remote service
        @type response: ndg.saml.saml2.core.Response
        @raise SubjectQueryResponseError: if a timestamp is invalid
        """
        
        if not self.verifyTimeConditions:
            log.debug("Skipping verification of SAML Response time conditions")
            
        utcNow = datetime.utcnow() 
        nowMinusSkew = utcNow - self.clockSkew
        nowPlusSkew = utcNow + self.clockSkew
        
        if response.issueInstant > nowPlusSkew:
            msg = ('SAML Attribute Response issueInstant [%s] is after '
                   'the clock time [%s] (skewed +%s)' % 
                   (response.issueInstant, 
                    SAMLDateTime.toString(nowPlusSkew),
                    self.clockSkew))
            
            samlRespError = AttributeQueryResponseError(msg)                  
            samlRespError.response = response
            raise samlRespError
        
        for assertion in response.assertions:
            if assertion.issueInstant is None:
                samlRespError = AttributeQueryResponseError("No issueInstant "
                                                            "set in response "
                                                            "assertion")
                samlRespError.response = response
                raise samlRespError
            
            elif nowPlusSkew < assertion.issueInstant:
                msg = ('The clock time [%s] (skewed +%s) is before the '
                       'SAML Attribute Response assertion issue instant [%s]' % 
                       (SAMLDateTime.toString(utcNow),
                        self.clockSkew,
                        assertion.issueInstant))
                samlRespError = AttributeQueryResponseError(msg)
                samlRespError.response = response
                raise samlRespError

            if assertion.conditions is not None:
                if nowPlusSkew < assertion.conditions.notBefore:
                    msg = ('The clock time [%s] (skewed +%s) is before the '
                           'SAML Attribute Response assertion conditions not '
                           'before time [%s]' % 
                           (SAMLDateTime.toString(utcNow),
                            self.clockSkew,
                            assertion.conditions.notBefore))
                              
                    samlRespError = AttributeQueryResponseError(msg)
                    samlRespError.response = response
                    raise samlRespError
                 
                if nowMinusSkew >= assertion.conditions.notOnOrAfter:           
                    msg = ('The clock time [%s] (skewed -%s) is on or after '
                           'the SAML Attribute Response assertion conditions '
                           'not on or after time [%s]' % 
                           (SAMLDateTime.toString(utcNow),
                            self.clockSkew,
                            assertion.conditions.notOnOrAfter))
                    
                    samlRespError = AttributeQueryResponseError(msg) 
                    samlRespError.response = response
                    raise samlRespError
                
    def send(self, **kw):
        '''Make an attribute query to a remote SAML service
        
        @type uri: basestring 
        @param uri: uri of service.  May be omitted if set from request.url
        @type request: ndg.security.common.soap.UrlLib2SOAPRequest
        @param request: SOAP request object to which query will be attached
        defaults to ndg.security.common.soap.client.UrlLib2SOAPRequest
        '''
        attributeQuery = self._createQuery()
            
        response = super(AttributeQuerySOAPBinding, self).send(attributeQuery, 
                                                               **kw)

        # Perform validation
        if response.status.statusCode.value != StatusCode.SUCCESS_URI:
            msg = ('Return status code flagged an error.  The message is: %r' %
                   response.status.statusMessage.value)
            samlRespError = AttributeQueryResponseError(msg)
            samlRespError.response = response
            raise samlRespError
        
        # Check Query ID matches the query ID the service received
        if response.inResponseTo != attributeQuery.id:
            msg = ('Response in-response-to ID %r, doesn\'t match the original '
                   'query ID, %r' % (response.inResponseTo, attributeQuery.id))
            
            samlRespError = AttributeQueryResponseError(msg)
            samlRespError.response = response
            raise samlRespError
        
        self._verifyTimeConditions(response)
        
        return response 

    
class AttributeQuerySslSOAPBinding(AttributeQuerySOAPBinding):
    """Specialisation of AttributeQuerySOAPbinding taking in the setting of
    SSL parameters for mutual authentication
    """
    SSL_CONTEXT_PROXY_SUPPORT = _sslContextProxySupport
    __slots__ = ('__sslCtxProxy',)
    
    def __init__(self, **kw):
        if not AttributeQuerySslSOAPBinding.SSL_CONTEXT_PROXY_SUPPORT:
            raise ImportError("ndg.security.common.utils.m2crypto import "
                              "failed - missing M2Crypto package?")
        
        # Miss out default HTTPSHandler and set in send() instead
        if 'handlers' in kw:
            raise TypeError("__init__() got an unexpected keyword argument "
                            "'handlers'")
            
        super(AttributeQuerySslSOAPBinding, self).__init__(handlers=(), **kw)
        self.__sslCtxProxy = SSLContextProxy()

    def send(self, **kw):
        """Override base class implementation to pass explicit SSL Context
        """
        httpsHandler = HTTPSHandler(ssl_context=self.sslCtxProxy.createCtx())
        self.client.openerDirector.add_handler(httpsHandler)
        return super(AttributeQuerySslSOAPBinding, self).send(**kw)
        
    @property
    def sslCtxProxy(self):
        """SSL Context Proxy object used for setting up an SSL Context for
        queries
        """
        return self.__sslCtxProxy
            
    def __setattr__(self, name, value):
        """Enable setting of SSLContextProxy attributes as if they were 
        attributes of this class.  This is intended as a convenience for 
        making settings parameters read from a config file
        """
        try:
            super(AttributeQuerySslSOAPBinding, self).__setattr__(name, value)
            
        except AttributeError:
            # Coerce into setting SSL Context Proxy attributes
            try:
                setattr(self.sslCtxProxy, name, value)
            except:
                raise
