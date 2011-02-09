"""NDG Logging Web service server side interface.  Generated and 
adapted from:

wsdl2dispatch -f log.wsdl

NERC Data Grid Project

P J Kershaw 12/05/06

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
import os

from log_services import *
from ZSI.ServiceContainer import ServiceSOAPBinding

from Log import *
from LogIO import *


class log(ServiceSOAPBinding):
    soapAction = {
        'urn:log#debug': 'soap_debug',
        'urn:log#error': 'soap_error',
        'urn:log#info': 'soap_info',
        'urn:log#warning': 'soap_warning',
        }

    def __init__(self, srv, debug=False, post='/log.wsdl', **kw):
        ServiceSOAPBinding.__init__(self, post)
        
        if not isinstance(srv, Log):
            raise LogError("Expecting NDG Log type object")
            
        self.__srv = srv        
        self.__debug = debug
        self.__caCertFilePath = os.path.expandvars(\
                                             "$NDG_DIR/conf/certs/cacert.pem")
        

    def soap_debug(self, ps):
        """Log a debug message"""

        if self.__debug:
            import pdb
            pdb.set_trace()        
        
        # input vals in request object
        reqArgs = ps.Parse(debugRequestWrapper)        
        req = DebugReq(xmlTxt=str(reqArgs._debugReq))        

        # assign return values to response object
        response = debugResponseWrapper()
        
        try:            
            if not req.isValidSig(self.__caCertFilePath):
                response._debugResp = "Client signature is invalid"
                
            self.__srv.debug(req['msg'])

        except Exception, e:
            response._debugResp = str(e)

        response._debugResp = ''
        return response


    def soap_error(self, ps):
        """Log an error message"""
        
        if self.__debug:
            import pdb
            pdb.set_trace()       
        
        # input vals in request object
        reqArgs = ps.Parse(errorRequestWrapper)
        req = ErrorReq(xmlTxt=str(reqArgs._errorReq))       

        # assign return values to response object
        response = errorResponseWrapper()
        
        try:
            if not req.isValidSig(self.__caCertFilePath):
                response._errorResp = "Client signature is invalid"
                
            self.__srv.error(req['msg'])

        except Exception, e:
            response._errorResp = str(e)

        response._errorResp = ''
        return response


    def soap_info(self, ps):
        """Log an information message"""
        
        if self.__debug:
            import pdb
            pdb.set_trace()
        
        # input vals in request object
        reqArgs = ps.Parse(infoRequestWrapper)
        req = InfoReq(xmlTxt=str(reqArgs._infoReq))       

        # assign return values to response object
        response = infoResponseWrapper()
        
        try:
            if not req.isValidSig(self.__caCertFilePath):
                response._infoResp = "Client signature is invalid"

            self.__srv.info(req['msg'])

        except Exception, e:
            response._infoResp = str(e)

        response._infoResp = ''
        return response


    def soap_warning(self, ps):
        """Log an warning message"""
        
        if self.__debug:
            import pdb
            pdb.set_trace()
        
        # input vals in request object
        reqArgs = ps.Parse(warningRequestWrapper)
        req = WarningReq(xmlTxt=str(reqArgs._warningReq))       

        # assign return values to response object
        response = warningResponseWrapper()
        
        try:
            if not req.isValidSig(self.__caCertFilePath):
                response._warningResp = "Client signature is invalid"
                
            self.__srv.warning(req['msg'])

        except Exception, e:
            response._warningResp = str(e)

        response._warningResp = ''
        return response
