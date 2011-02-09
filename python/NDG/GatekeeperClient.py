#!/usr/bin/env python

"""NDG Gatekeeper client - client interface class to NDG Gatekeeper WS

NERC Data Grid Project

P J Kershaw 19/05/06

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

from ZSI import ServiceProxy
from ZSI.wstools.Utility import HTTPResponse
import sys
import os

from NDG.AttCert import *


#_____________________________________________________________________________
class GatekeeperClientError(Exception):
    """Exception handling for Gatekeeper class"""
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg


#_____________________________________________________________________________
class GatekeeperClient(object):
    
    #_________________________________________________________________________
    def __init__(self, wsdl=None, traceFile=None):
        """
        wsdl:                  WSDL URI for Gatekeeper WS.  Setting 
                               it will set the Service Proxy
        traceFile:             set to file object such as sys.stderr to 
                               give extra WS debug information"""

        self.__srvPx = None
        self.__wsdl = None
        
            
        self.__traceFile = traceFile
        
        if wsdl: 
            self.__setWSDL(wsdl)
            
            # Instantiate Gatekeeper WS proxy
            self.serviceProxy()
        

    #_________________________________________________________________________
    def __setWSDL(self, wsdl):
        
        if not isinstance(wsdl, basestring):
            raise GatekeeperClientError(\
                        "Gatekeeper WSDL URI must be a valid string")
        
        self.__wsdl = wsdl
        
    wsdl = property(fset=__setWSDL,doc="Set Gatekeeper WSDL URI")
    
        
    #_________________________________________________________________________
    def serviceProxy(self, wsdl=None):
        """Set the WS proxy for the Gatekeeper"""
        if wsdl:
            self.__setWSDL(wsdl)

        try:
            self.__srvPx = ServiceProxy(self.__wsdl, 
                                        use_wsdl=True, 
                                        tracefile=self.__traceFile)
        except HTTPResponse, e:
            raise GatekeeperClientError, \
                "Error initialising WSDL Service Proxy for \"%s\": %s %s" % \
                (self.__wsdl, e.status, e.reason)
                
        except Exception, e:
            raise GatekeeperClientError, \
                    "Initialising WSDL Service Proxy: " + str(e)

                                    
    #_________________________________________________________________________
    def readAccess(self, attCert=None, attCertFilePath=None):
        """Check Gatekeeper for read access to resource
        
        Pass attCert as an AttCert instance, a string containing XML or set
        a file path to attCertFilePath"""

        try:
            if attCertFilePath:
                attCert = AttCertRead(attCertFilePath)
                
            # str call allows an AttCert type to be passed as well as string
            # version
            resp = self.__srvPx.readAccess(attCert=str(attCert))
            
        except Exception, e:
            raise GatekeeperClientError("Error checking read access: "+str(e))
                              
        if resp['errMsg']:
            raise GatekeeperClientError(resp['errMsg'])
        
        return resp['matchingRole']

                                    
    #_________________________________________________________________________
    def writeAccess(self, attCert=None, attCertFilePath=None):
        """Check Gatekeeper for write access to resource
        
        Pass attCert as an AttCert instance, a string containing XML or set
        a file path to attCertFilePath"""

        try:
            if attCertFilePath:
                attCert = AttCertRead(attCertFilePath)
                
            # str call allows an AttCert type to be passed as well as string
            # version
            resp = self.__srvPx.writeAccess(attCert=str(attCert))
            
        except Exception, e:
            raise GatekeeperClientError,"Error checking write access: "+str(e)
                              
        if resp['errMsg']:
            raise GatekeeperClientError(resp['errMsg'])
        
        return resp['matchingRole']

                                    
    #_________________________________________________________________________
    def executeAccess(self, attCert=None, attCertFilePath=None):
        """Check Gatekeeper for execute access to resource
        
        Pass attCert as an AttCert instance, a string containing XML or set
        a file path to attCertFilePath"""

        try:
            if attCertFilePath:
                attCert = AttCertRead(attCertFilePath)
                
            # str call allows an AttCert type to be passed as well as string
            # version
            resp = self.__srvPx.executeAccess(attCert=str(attCert))
            
        except Exception, e:
            raise GatekeeperClientError,\
                                    "Error checking execute access: " + str(e)
                              
        if resp['errMsg']:
            raise GatekeeperClientError(resp['errMsg'])
        
        return resp['matchingRole']
  