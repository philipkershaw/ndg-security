#!/usr/bin/env python

"""NDG Logging client - client interface class to NDG Logging WS

NERC Data Grid Project

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
__author__ = "P J Kershaw"
__date__ = "12/05/06"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = "$Id$"

from ZSI import ServiceProxy
from ZSI.wstools.Utility import HTTPResponse
import sys
import os
import logging

from LogIO import *


class SOAPHandler(Handler):
    """
    A handler class which writes logging records, appropriately formatted,
    over a SOAP interface to logging web service
    """
    def __init__(self, *args, **kw):
        """Initialize the handler.

        """
        Handler.__init__(self)
        self._logClnt = LogClient(*args, **kw)

    def emit(self, record):
        """
        Emit a record.

        If a formatter is specified, it is used to format the record.
        The record is then written to the stream with a trailing newline
        [N.B. this may be removed depending on feedback]. If exception
        information is present, it is formatted using
        traceback.print_exception and appended to the stream.
        """
        try:
            msg = self.format(record)
            fs = "%s\n"
            if not hasattr(types, "UnicodeType"): #if no unicode support...
                self.stream.write(fs % msg)
            else:
                try:
                    self.stream.write(fs % msg)
                except UnicodeError:
                    self.stream.write(fs % msg.encode("UTF-8"))
            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)

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
                 uri=None,
                 signingCertFilePath=None,
                 signingPriKeyFilePath=None,
                 signingPriKeyPwd=None, 
                 traceFile=None):
        """
        uri:                   URI for Logging WS.  Setting 
                               it will set the Service Proxy
        traceFile:             set to file object such as sys.stderr to 
                               give extra WS debug information"""

        self.__srvPx = None
        self.__uri = None
        
        
        if uri:
            self.__setWSDL(uri)
           
        self.__traceFile = traceFile
        
        self.__signingCertFilePath = signingCertFilePath
        self.__signingPriKeyFilePath = signingPriKeyFilePath
        self.__signingPriKeyPwd = signingPriKeyPwd

         
        # Instantiate Logging WS proxy
        if self.__uri:
            self.serviceProxy()
        

    #_________________________________________________________________________
    def __setWSDL(self, uri):
        
        if not isinstance(uri, basestring):
            raise LogClientError, "Logging WSDL URI must be a valid string"
        
        self.__uri = uri
        
    uri = property(fset=__setURI,doc="Set Logging WSDL URI")
    
        
    #_________________________________________________________________________
    def serviceProxy(self, uri=None):
        """Set the WS proxy for the Logging"""
        if uri:
            self.__setURI(uri)

        try:
            self.__srvPx = ServiceProxy(self.__uri, 
                                        use_uri=True, 
                                        tracefile=self.__traceFile)
        except HTTPResponse, e:
            raise LogClientError, \
                "Error initialising URI Service Proxy for \"%s\": %s %s" % \
                (self.__uri, e.status, e.reason)

        except Exception, e:
            raise LogClientError, \
                    "Initialising URI Service Proxy: " + str(e)

                                    
    #_________________________________________________________________________
    def debug(self, msg):
        """Send a debug message to the log"""

        try:
            debugReq = DebugReq(msg=msg)                   
            debugReq.sign(self.__signingPriKeyFilePath,
                          self.__signingPriKeyPwd,
                          self.__signingCertFilePath)
        
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
                         self.__signingCertFilePath)
        
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
                            self.__signingCertFilePath)
        
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
                          self.__signingCertFilePath)
        
            resp = self.__srvPx.error(errorReq=errorReq())
            
        except Exception, e:
            raise LogClientError("Error sending error message: " + str(e))
                              
        if resp['errorResp']:
            raise LogClientError(resp['errorResp'])


     