"""WSGI Middleware for WS-Security

Implements Digital Signature handling based around ZSI

NERC Data Grid Project"""
__author__ = "P J Kershaw"
__date__ = "11/06/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import logging
log = logging.getLogger(__name__)

from ZSI.parse import ParsedSoap

from ZSI.writer import SoapWriter
from ndg.security.common.wssecurity.signaturehandler.foursuite import \
    SignatureHandler
from ndg.security.server.wsgi.zsi import ZSIMiddleware, ZSIMiddlewareError

class WSSecurityFilterError(ZSIMiddlewareError):
    """Base exception class for WS-Security WSGI Filter"""
    _log = log
    
class WSSecurityFilterConfigError(WSSecurityFilterError):
    """WS-Security Filter Config Error"""
 
class WSSecurityFilter(ZSIMiddleware):
    """Base class for WS-Security filters
    
    Overload pathMatch lambda so that it is more inclusive: the default is
    for all paths to be processed by the handlers"""
    pathMatch = lambda self, environ: environ['PATH_INFO'].startswith(self.path)


class SignatureFilter(WSSecurityFilter):
    """Base class for WS-Security signature and signature verification filters
    """
    WSSE_CFG_FILEPATH_OPTNAME = 'wsseCfgFilePath'
    WSSE_CFG_FILE_SECTION_OPTNAME = 'wsseCfgFileSection'
    WSSE_CFG_FILE_PREFIX_OPTNAME = 'wsseCfgFilePrefix'
    
    def __init__(self, app):
        super(SignatureFilter, self).__init__(app)
        self.__signatureHandler = None
        
    def initialise(self, global_conf, prefix='', **app_conf):
        """Set-up Signature filter attributes using a Paste app factory 
        pattern.  
        
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        super(SignatureFilter, self).initialise(global_conf, **app_conf)

        # Where possible remove keywords not applicable to SignatureHandler
        wsseCfgFilePath = app_conf.pop(
                        prefix+SignatureFilter.WSSE_CFG_FILEPATH_OPTNAME, 
                        None)
        wsseCfgFileSection = app_conf.pop(
                        prefix+SignatureFilter.WSSE_CFG_FILE_SECTION_OPTNAME, 
                        None)
        wsseCfgFilePrefix = app_conf.pop(
                        prefix+SignatureFilter.WSSE_CFG_FILE_PREFIX_OPTNAME, 
                        None)
        
        self.signatureHandler = SignatureHandler(cfg=wsseCfgFilePath,
                                            cfgFileSection=wsseCfgFileSection,
                                            cfgFilePrefix=wsseCfgFilePrefix,
                                            **app_conf)

    def _getSignatureHandler(self):
        return self.__signatureHandler

    def _setSignatureHandler(self, value):
        if not isinstance(value, SignatureHandler):
            raise TypeError('Expecting %r for "signatureHandler"; got %r' %
                            (SignatureHandler, type(value)))
        self.__signatureHandler = value

    signatureHandler = property(_getSignatureHandler, 
                                _setSignatureHandler, 
                                doc="Signature Handler Class")
           
    
class ApplySignatureFilter(SignatureFilter):
    '''Apply WS-Security digital signature to SOAP message'''
    WSSE_SIGNATURE_VERIFICATION_FILTERID_OPTNAME = \
        'wsseSignatureVerificationFilterID'
        
    def __init__(self, app):
        super(ApplySignatureFilter, self).__init__(app)
        self.__wsseSignatureVerificationFilterID = None
        
    def initialise(self, global_conf, **app_conf):
        """Set-up Signature filter attributes using a Paste app factory 
        pattern.  
        
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        super(ApplySignatureFilter, self).initialise(global_conf, **app_conf)
        self.wsseSignatureVerificationFilterID = app_conf.pop(
            ApplySignatureFilter.WSSE_SIGNATURE_VERIFICATION_FILTERID_OPTNAME,
            '')

    def _getWsseSignatureVerificationFilterID(self):
        return self.__wsseSignatureVerificationFilterID

    def _setWsseSignatureVerificationFilterID(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string for '
                            '"wsseSignatureVerificationFilterID"; got %r' %
                            type(value))
        self.__wsseSignatureVerificationFilterID = value

    wsseSignatureVerificationFilterID = property(
                                        _getWsseSignatureVerificationFilterID, 
                                        _setWsseSignatureVerificationFilterID, 
                                        doc="Keyword to reference the "
                                            "Signature Verification filter if "
                                            "any in the WSGI environ")

    def __call__(self, environ, start_response):
        '''Sign message'''
        if not ApplySignatureFilter.isSOAPMessage(environ) or \
           not self.pathMatch(environ):
            log.debug("ApplySignatureFilter.__call__: Non-SOAP request or "
                      "path doesn't match SOAP endpoint specified - skipping "
                      "signature verification")
            return self._app(environ, start_response)
        
        log.debug('Signing outbound message ...')
        if ApplySignatureFilter.isSOAPFaultSet(environ):
            # TODO: If the Signature handler is signing any sub-elements in the
            # message body this is going to run into problems because the 
            # fault content is obviously going to be different.
            # TODO: Should SOAP faults be signed at all?
            log.warning("Attempting to sign a SOAP fault message...")
         
        # The following is broken into two try blocks so that exceptions 
        # raised from the 1st can still returned as signed SOAP faults back to 
        # the client 
        try:
            sw = ApplySignatureFilter.getSOAPWriter(environ)
            
            # Copy signature value in order to apply signature confirmation
            if self.signatureHandler.applySignatureConfirmation:
                filter = environ.get(self.wsseSignatureVerificationFilterID)
                if filter is None:
                    raise WSSecurityFilterConfigError(
                        'SignatureHandler "applySignatureConfirmation" flag '
                        'is set to True but no Signature Verification Filter '
                        'has been set in the environ: check that the '
                        '"wsseSignatureVerificationFilterID" property is set '
                        'and that it references the "filterID" set for the '
                        'verification filter')
                    
                self.signatureHandler.b64EncSignatureValue = \
                                filter.signatureHandler.b64EncSignatureValue
        except Exception, e:
            sw = self.exception2SOAPFault(environ, e)
            ApplySignatureFilter.setSOAPWriter(environ, sw)
         
        try:
            self.signatureHandler.sign(sw)
        except Exception, e:
            sw = self.exception2SOAPFault(environ, e)
            ApplySignatureFilter.setSOAPWriter(environ, sw)
        
        return self.writeResponse(environ, start_response)
    

class SignatureVerificationFilter(SignatureFilter):
    '''Verify WS-Security digital signature in SOAP message'''
    
    def __call__(self, environ, start_response):
        '''Verify message signature'''
        if not SignatureVerificationFilter.isSOAPMessage(environ) or \
           not self.pathMatch(environ):
            log.debug("SignatureVerificationFilter.__call__: Non-SOAP "
                      "request or path doesn't match SOAP endpoint specified "
                      "- skipping signature verification")
            return self._app(environ, start_response)

        log.debug("Verifying inbound message signature...")

        # Add a reference to this filter in environ so that other middleware
        # can reference it
        self.addFilter2Environ(environ)
        
        try:
            ps = self.parseRequest(environ)
            self.signatureHandler.verify(ps)
        except Exception, e:
            sw = self.exception2SOAPFault(environ, e)
            SignatureVerificationFilter.setSOAPWriter(environ, sw)
            
        return self.writeResponse(environ, start_response)
