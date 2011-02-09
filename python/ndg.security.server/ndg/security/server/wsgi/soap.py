"""NDG Security SOAP Service Middleware

NERC Data Grid Project

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
__author__ = "P J Kershaw"
__date__ = "27/05/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

import paste.request
from ZSI import EvaluateException, ParseException
from ZSI.parse import ParsedSoap
from ZSI.writer import SoapWriter
from ZSI import fault

from ZSI.ServiceContainer import ServiceSOAPBinding
from ndg.security.common.utils.classfactory import instantiateClass
     
class SOAPMiddlewareError(Exception):
    """Base error handling exception class for the SOAP WSGI middleware module
    """
    _log = log
    def __init__(self, *arg, **kw):
        '''Extend to enable logging of errors'''
        if len(arg) > 0:
            self.__class__._log.error(arg[0])
        Exception.__init__(self, *arg, **kw)
    
class SOAPMiddlewareReadError(SOAPMiddlewareError):
    """SOAP Middleware read error"""

class SOAPMiddlewareConfigError(SOAPMiddlewareError):
    """SOAP Middleware configuration error"""

class SOAPMiddleware(object):
    '''Middleware configurable to a given ZSI SOAP binding'''  
    
    soapWriterKey = 'ZSI.writer.SoapWriter'
    parsedSOAPKey = 'ZSI.parse.ParsedSoap'
    soapFaultSetKey = 'ndg.security.server.wsgi.soap.soapFault'
    
    def __init__(self, app, app_conf, **kw):
        log.debug("SOAPMiddleware.__init__ ...")
        self.app = app
        self.app_conf = app_conf
        self.app_conf.update(kw)
        
        if 'charset' in self.app_conf:
            self.app_conf['charset'] = '; charset=' + self.app_conf['charset']
        else:
            self.app_conf['charset'] = '; charset=utf-8'

        if 'path' in self.app_conf:
            if self.app_conf['path'] != '/':
                self.app_conf['path'] = self.app_conf['path'].rstrip('/')
        else:
            self.app_conf['path'] = '/'

        # This flag if set to True causes this handler to call the 
        # start_response method and output the SOAP response
        self.writeResponseSet = self.app_conf.get('writeResponse', 
                                                  'false').lower() == 'true'

        # Check for a list of other filters to be referenced by this one
        if 'referencedFilters' in self.app_conf:
            # __call__  may reference any filters in environ keyed by these
            # keywords
            self.referencedFilterKeys = \
                                self.app_conf.pop('referencedFilters').split()
                                
            # Remove equivalent keyword if present
            kw.pop('referencedFilters', None)
            

    def __call__(self, environ, start_response):
        log.debug("SOAPMiddleware.__call__")
                        
        # Derived class must implement SOAP Response via overloaded version of
        # this method.  ParsedSoap object is available as a key in environ via
        # the parseRequest method
        
        return self.writeResponse(environ, start_response)

    
    def _initCall(self, environ, start_response):
        '''Sub-divided out from __call__ to enable derived classes to easily
        include this functionality:
         - Set a reference to this WSGI filter in environ if filterID was 
        set in the config and 
         - check the request to see if this filter should handle it
        '''
        
        # Add any filter references for this WSGI component regardless of the
        # current request ID.  This ensures that other WSGI components called
        # may reference it if they need to.
        self.addFilter2Environ(environ)
        
        # Apply filter for calls
        if not self.isSOAPMessage(environ):
            log.debug("SOAPMiddleware.__call__: skipping non-SOAP call")
            return self.app(environ, start_response)
        
        elif not self.pathMatch(environ):
            log.debug("SOAPMiddleware.__call__: path doesn't match SOAP "
                      "service endpoint")
            return self.app(environ, start_response)
        
        elif self.isSOAPFaultSet(environ):
            # This MUST be checked in a overloaded version especially in 
            # consideration of security: e.g. an upstream signature 
            # verification may have found an error in a signature
            log.debug("SOAPMiddleware.__call__: SOAP fault set by previous "
                      "SOAP middleware filter")
            return self.app(environ, start_response)

        # Parse input into a ZSI ParsedSoap object set as a key in environ
        try:
            self.parseRequest(environ)
        except Exception, e:
            sw = self.exception2SOAPFault(environ, e)
            self.setSOAPWriter(environ, sw)
            return self.writeResponse(environ, start_response)
        
        # Return None to __call__ to indicate that it can proceed with 
        # processing the input
        return None

    @classmethod
    def exception2SOAPFault(cls, environ, exception):
        '''Convert an exception into a SOAP fault message'''
        soapFault = fault.FaultFromException(exception, None)
        sw = SoapWriter()
        soapFault.serialize(sw)
        environ[cls.soapFaultSetKey] = 'True'
        return sw
    
    pathMatch = lambda self,environ:environ['PATH_INFO']==self.app_conf['path']
        
    @staticmethod
    def isSOAPMessage(environ):
        '''Generic method to filter out non-soap messages
        
        TODO: is HTTP_SOAPACTION only set for WSDL doc-literal wrapped style
        generated content? - If so this test should be moved'''
        return environ.get('REQUEST_METHOD', '') == 'POST' and \
               environ.get('HTTP_SOAPACTION') is not None

    @classmethod
    def isSOAPFaultSet(cls, environ):
        '''Check environment for SOAP fault flag set.  This variable is set
        from exception2SOAPFault'''
        return bool(environ.get(cls.soapFaultSetKey, False)) == True
    
    @classmethod
    def parseRequest(cls, environ):
        '''Parse SOAP message from environ['wsgi.input']
        
        Reading from environ['wsgi.input'] may be a destructive process so the
        content is saved in a ZSI.parse.ParsedSoap object for use by SOAP
        handlers which follow in the chain
        
        environ['ZSI.parse.ParsedSoap'] may be set to a ParsedSoap object
        parsed by a SOAP handler ahead of the current one in the chain.  In
        this case, don't re-parse.  If NOT parsed, parse and set
        'ZSI.parse.ParsedSoap' environ key'''
        
        # Check for ParsedSoap object set in environment, if not present,
        # make one
        ps = environ.get(cls.parsedSOAPKey)
        if ps is None:
            # TODO: allow for chunked data
            contentLength = int(environ['CONTENT_LENGTH'])
            soapIn = environ['wsgi.input'].read(contentLength)
            if len(soapIn) < contentLength:
                raise SOAPMiddlewareReadError("Expecting %d content length; "
                                              "received %d instead." % 
                                              (contentLength, len(soapIn)))
            
            log.debug("SOAP Request for handler %r" % cls)
            log.debug("_"*80)
            log.debug(soapIn)
            log.debug("_"*80)
            
            ps = ParsedSoap(soapIn)
            environ[cls.parsedSOAPKey] = ps
            
        return environ[cls.parsedSOAPKey]


    def writeResponse(self, environ, start_response, errorCode=None):
        '''This method serializes the SOAP output and sets the response header.
        It's the final step and should be called in the last SOAP handler in 
        a chain of handlers or else specify it in the ini file as the last
        SOAP handler'''
        
        # This flag must be set to True to write out the final response from
        # this handler
        if self.writeResponseSet == False:
            return self.app(environ, start_response)
        
        sw = self.getSOAPWriter(environ)
        soapOut = str(sw)
        charset = self.app_conf['charset']
        
        if errorCode is None:
            if self.isSOAPFaultSet(environ):
                errorCode = "500 Internal Server Error"
            else:
                errorCode = "200 OK"
                
        log.debug("SOAP Response for handler %r" % self.__class__)
        log.debug("_"*80)
        log.debug(soapOut)
        log.debug("_"*80)
        start_response(errorCode,
                       [('content-type', 'text/xml'+charset),
                        ('content-length', str(len(soapOut)))])
        return soapOut

    @classmethod
    def getSOAPWriter(cls, environ):
        '''Access SoapWriter object set in environment by this classes' call
        method'''
        
        sw = environ.get(SOAPMiddleware.soapWriterKey)
        if sw is None:
            raise KeyError("Expecting '%s' key in environ: missing call to "
                           "SOAPMiddleware?" % SOAPMiddleware.soapWriterKey)
        return sw
    
    @classmethod
    def setSOAPWriter(cls, environ, sw):
        '''Set SoapWriter object in environment'''   
        environ[SOAPMiddleware.soapWriterKey] = sw

    def addFilter2Environ(self, environ):
        '''Add a key to the current application in the environment so that
        other middleware can reference it.  This is dependent on filterID set
        in app_conf'''
        filterID = self.app_conf.get('filterID')
        if filterID is not None:           
            if filterID in environ:
                raise SOAPMiddlewareConfigError("An filterID key '%s' is "
                                                "already set in environ" %
                                                filterID)
            environ[filterID] = self
            
        
class SOAPBindingMiddleware(SOAPMiddleware):  
    '''Apply a ZSI ServiceSOAPBinding type SOAP service'''
         
    def __init__(self, *arg, **kw):
        
        super(SOAPBindingMiddleware, self).__init__(*arg, **kw)
        
        # Check for Service binding in config
        if 'ServiceSOAPBindingClass' in self.app_conf:
            modName, className = \
                        self.app_conf['ServiceSOAPBindingClass'].rsplit('.', 1)
            
            self.serviceSOAPBinding = instantiateClass(modName, 
                                   className, 
                                   objectType=ServiceSOAPBinding, 
                                   classProperties=self.serviceSOAPBindingKw)            
        else: 
            self.serviceSOAPBinding = ServiceSOAPBinding()
        
        # Flag to enable display of WSDL via wsdl query arg in a GET request
        self.enableWSDLQuery = self.app_conf.get('enableWSDLQuery', False) and\
                                hasattr(self.serviceSOAPBinding, '_wsdl')


    def _getServiceSOAPBindingKw(self):
        '''Extract keywords to specific to SOAP Service Binding set in app_conf
        '''
        if 'ServiceSOAPBindingPropPrefix' not in self.app_conf:
            return {}
        
        prefix = self.app_conf['ServiceSOAPBindingPropPrefix']+'.'
        serviceSOAPBindingKw = dict([(k.replace(prefix, ''), v) \
                                     for k,v in self.app_conf.items() \
                                     if k.startswith(prefix)])
        return serviceSOAPBindingKw
    
    serviceSOAPBindingKw = property(fget=_getServiceSOAPBindingKw)
    
    def __call__(self, environ, start_response):
        log.debug("SOAPBindingMiddleware.__call__ ...")
                
        if self.pathMatch(environ) and self.enableWSDLQuery and \
           environ.get('REQUEST_METHOD', '') == 'GET' and \
           environ.get('QUERY_STRING', '') == 'wsdl':
            wsdl = self.serviceSOAPBinding._wsdl
            start_response("200 OK", [('Content-type', 'text/xml'),
                                      ('Content-length', str(len(wsdl)))])
            return wsdl
                
                
        # Apply filter for calls
        response = self._initCall(environ, start_response)
        if response is not None:
            return response
        
        
        try:
            # Other filters in the middleware chain may be passed by setting
            # a reference to them in the config.  This is useful if the SOAP
            # binding code needs to access results from upstream middleware 
            # e.g. check output from signature verification filter
            if hasattr(self, 'referencedFilterKeys'):
                try:
                    self.serviceSOAPBinding.referencedWSGIFilters = \
                                    dict([(i, environ[i]) 
                                          for i in self.referencedFilterKeys])
                except KeyError:
                    raise SOAPMiddlewareConfigError('No filter ID "%s" found '
                                                    'in environ' % i)    
            ps = self.parseRequest(environ)
            
            # Map SOAP Action to method in binding class
            soapMethodName = 'soap_%s' % environ['HTTP_SOAPACTION'].strip('"')
            
            method = getattr(self.serviceSOAPBinding, soapMethodName)            
            resp = method(ps)
        except Exception, e:
            sw = self.exception2SOAPFault(environ, e)
        else: 
            # Serialize output using SOAP writer class
            sw = SoapWriter()
            sw.serialize(resp)
        
        # Make SoapWriter object available to any SOAP filters that follow
        self.setSOAPWriter(environ, sw)
        
        soapOut = str(sw)
        charset = self.app_conf['charset']

        return self.writeResponse(environ, start_response)
