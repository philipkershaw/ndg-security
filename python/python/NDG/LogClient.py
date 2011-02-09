#!/usr/bin/env python

"""NDG Logging client - client interface class to NDG Logging WS

NERC Data Grid Project

P J Kershaw 12/05/06

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

from ZSI import ServiceProxy
import sys
import os

from LogIO import *

#_____________________________________________________________________________
class LogClientError(Exception):
    """Exception handling for Logging class"""
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg


#_____________________________________________________________________________
class LogClient(object):
    
    #_________________________________________________________________________
    def __init__(self, 
                 wsdl=None,
                 signingPubKeyFilePath=None,
                 signingPriKeyFilePath=None,
                 signingPriKeyPwd=None, 
                 traceFile=None):
        """
        wsdl:                  WSDL URI for Logging WS.  Setting 
                               it will set the Service Proxy
        traceFile:             set to file object such as sys.stderr to 
                               give extra WS debug information"""

        self.__srvPx = None
        self.__wsdl = None
        
        
        if wsdl:
            self.__setWSDL(wsdl)
           
        self.__traceFile = traceFile
        
        self.__signingPubKeyFilePath = signingPubKeyFilePath
        self.__signingPriKeyFilePath = signingPriKeyFilePath
        self.__signingPriKeyPwd = signingPriKeyPwd

         
        # Instantiate Logging WS proxy
        if self.__wsdl:
            self.serviceProxy()
        

    #_________________________________________________________________________
    def __setWSDL(self, wsdl):
        
        if not isinstance(wsdl, basestring):
            raise LogClientError(\
                        "Logging WSDL URI must be a valid string")
        
        self.__wsdl = wsdl
        
    wsdl = property(fset=__setWSDL,doc="Set Logging WSDL URI")
    
        
    #_________________________________________________________________________
    def serviceProxy(self, wsdl=None):
        """Set the WS proxy for the Logging"""
        if wsdl:
            self.__setWSDL(wsdl)

        try:
            self.__srvPx = ServiceProxy(self.__wsdl, 
                                        use_wsdl=True, 
                                        tracefile=self.__traceFile)
        except Exception, e:
            raise LogClientError(\
                    "Initialising WSDL Service Proxy: " + str(e))

                                    
    #_________________________________________________________________________
    def debug(self, msg):
        """Send a debug message to the log"""

        try:
            debugReq = DebugReq(msg=msg)                   
            debugReq.sign(self.__signingPriKeyFilePath,
                          self.__signingPriKeyPwd,
                          self.__signingPubKeyFilePath)
        
            resp = self.__srvPx.debug(debugReq=debugReq())
            
        except Exception, e:
            raise LogClientError("Error sending debug message: " + str(e))
                              
        if resp['debugResp']:
            raise LogClientError(resp['debugResp'])

                                    
    #_________________________________________________________________________
    def info(self, msg):
        """Send a information message to the log"""

        try:   
            infoReq = InfoReq(msg=msg)                    
            infoReq.sign(self.__signingPriKeyFilePath,
                         self.__signingPriKeyPwd,
                         self.__signingPubKeyFilePath)
        
            resp = self.__srvPx.info(infoReq=infoReq())
            
        except Exception, e:
            raise LogClientError("Error sending info message: " + str(e))
                              
        if resp['infoResp']:
            raise LogClientError(resp['infoResp'])

                                    
    #_________________________________________________________________________
    def warning(self, msg):
        """Send a warning message to the log"""

        try:   
            warningReq = WarningReq(msg=msg)                     
            warningReq.sign(self.__signingPriKeyFilePath,
                            self.__signingPriKeyPwd,
                            self.__signingPubKeyFilePath)
        
            resp = self.__srvPx.warning(warningReq=warningReq())
            
        except Exception, e:
            raise LogClientError("Error sending warning message: " + str(e))
                              
        if resp['warningResp']:
            raise LogClientError(resp['warningResp'])

                                    
    #_________________________________________________________________________
    def error(self, msg):
        """Send a error message to the log"""

        try:   
            errorReq = ErrorReq(msg=msg)                     
            errorReq.sign(self.__signingPriKeyFilePath,
                          self.__signingPriKeyPwd,
                          self.__signingPubKeyFilePath)
        
            resp = self.__srvPx.error(errorReq=errorReq())
            
        except Exception, e:
            raise LogClientError("Error sending error message: " + str(e))
                              
        if resp['errorResp']:
            raise LogClientError(resp['errorResp'])


     