"""WSGI Middleware for WS-Security

Implements Digital Signature handling based around ZSI

NERC Data Grid Project"""
__author__ = "P J Kershaw"
__date__ = "11/06/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import logging
log = logging.getLogger(__name__)

from ZSI.parse import ParsedSoap

from ZSI.writer import SoapWriter
from ndg.security.common.wssecurity.dom import SignatureHandler
from ndg.security.server.wsgi.soap import SOAPMiddleware, SOAPMiddlewareError

class WSSecurityFilterError(SOAPMiddlewareError):
    """Base exception class for WS-Security WSGI Filter"""
    _log = log
    
class WSSecurityFilterConfigError(WSSecurityFilterError):
    """WS-Security Filter Config Error"""
 
class WSSecurityFilter(SOAPMiddleware):
    """Base class for WS-Security filters
    
    Overload pathMatch lambda so that it is more inclusive: the default is
    for all paths to be processed by the handlers"""
    pathMatch = lambda self, environ: \
                        environ['PATH_INFO'].startswith(self.app_conf['path'])

class SignatureFilter(WSSecurityFilter):
    """Base class for WS-Security signature and signature verification filters
    """
    def __init__(self, app, app_conf, **kw):
        super(SignatureFilter, self).__init__(app, app_conf, **kw)
        
        wsseCfgFilePath = self.app_conf.get('wsseCfgFilePath')        
        wsseCfgFileSection = self.app_conf.get('wsseCfgFileSection')
        wsseCfgFilePrefix = self.app_conf.get('wsseCfgFilePrefix')
        
        # Where possible remove keywords not applicable to SignatureHandler
        kw.pop('wsseCfgFilePath', None)
        kw.pop('wsseCfgFileSection', None)
        kw.pop('wsseCfgFilePrefix', None)
        
        self.signatureHandler = SignatureHandler(cfg=wsseCfgFilePath,
                                            cfgFileSection=wsseCfgFileSection,
                                            cfgFilePrefix=wsseCfgFilePrefix,
                                            **kw)
           
    
class ApplySignatureFilter(SignatureFilter):
    '''Apply WS-Security digital signature to SOAP message'''
    def __init__(self, *arg, **kw):
        '''Extend SignatureFilter.__init__ to enable setting of
        WS-Security signature verification filter from config'''
        self.wsseSignatureVerificationFilterID = kw.pop(
                                        'wsseSignatureVerificationFilterID', 
                                        None)
        
        super(ApplySignatureFilter, self).__init__(*arg, **kw)

    def __call__(self, environ, start_response):
        '''Sign message'''
        if not self.isSOAPMessage(environ) or \
           not self.pathMatch(environ):
            log.debug("ApplySignatureFilter.__call__: Non-SOAP request or "
                      "path doesn't match SOAP endpoint specified - skipping "
                      "signature verification")
            return self.app(environ, start_response)
        
        log.debug('Signing outbound message ...')
        if self.isSOAPFaultSet(environ):
            # TODO: If the Signature handler is signing any sub-elements in the
            # message body this is going to run into problems because the 
            # fault content is obviously going to be different.
            # TODO: Should SOAP faults be signed at all?
            log.warning("Attempting to sign a SOAP fault message...")
         
        # The following is broken into two try blocks so that exceptions 
        # raised from the 1st can still returned as signed SOAP faults back to 
        # the client 
        try:
            sw = self.getSOAPWriter(environ)
            
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
            self.setSOAPWriter(environ, sw)

            
        try:
            self.signatureHandler.sign(sw)
        except Exception, e:
            sw = self.exception2SOAPFault(environ, e)
            self.setSOAPWriter(environ, sw)
        
        return self.writeResponse(environ, start_response)
    

class SignatureVerificationFilter(SignatureFilter):
    '''Verify WS-Security digital signature in SOAP message'''
    
    def __call__(self, environ, start_response):
        '''Verify message signature'''
        if not self.isSOAPMessage(environ) or \
           not self.pathMatch(environ):
            log.debug("SignatureVerificationFilter.__call__: Non-SOAP "
                      "request or path doesn't match SOAP endpoint specified "
                      "- skipping signature verification")
            return self.app(environ, start_response)

        log.debug("Verifying inbound message signature...")

        # Add a reference to this filter in environ so that other middleware
        # can reference it
        self.addFilter2Environ(environ)
        
        try:
            ps = self.parseRequest(environ)
            self.signatureHandler.verify(ps)
        except Exception, e:
            sw = self.exception2SOAPFault(environ, e)
            self.setSOAPWriter(environ, sw)
            
        return self.writeResponse(environ, start_response)
