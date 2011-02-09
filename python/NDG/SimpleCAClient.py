"""Client to NDG SimpleCA WS

NERC Data Grid Project

P J Kershaw 08/08/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later."""

cvsID = '$Id$'

import types
import cElementTree as ElementTree
from ZSI import ServiceProxy
import socket # handle socket errors from WS
from CertReq import *

# Allow dictionary like behaviour for SimpleCAClient class
from UserDict import UserDict


#_____________________________________________________________________________
class SimpleCAClientError(Exception):    
    """Exception handling for NDG Certificate Request class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg
    



#_____________________________________________________________________________
class SimpleCAClient(UserDict):
    """Implements ZSI client to SimpleCA WS"""

    # valid configuration property keywords
    __validKeys = ['wsdl',
                   'xmlSigCertFile',
                   'xmlSigKeyFile',
                   'xmlSigCertPPhrase']
    
    def __init__(self,
                 propFilePath=None,
                 propElem=None,
                 bInitSrvPx=True,
                 **prop):        
        """Initialise WS client to SimpleCA

        propFilePath:       properties set via config file
        bInitSrvPx:         initialise WS proxy - this can be called
                            separately
        **prop:             properties can be set via input keywords.  Nb.
                            if a properties file has been set it's properties
                            will override these settings"""

        # Properties set via input keywords
        self.__prop = {}
        self.setProperties(**prop)


        # Properties set in file override if equivalent is present in
        # properties file 
        if propFilePath or propElem:
            self.readProperties(propFilePath, propElem)


        # Set up Web Service proxy - if WSDL has been set input flag set also
        if bInitSrvPx and 'wsdl' in self.__prop:
            self.initSrvPx()
        else:
            self.__srvPx = None


    #_________________________________________________________________________
    # UserDict derived methods ...
    #
    # Nb. read only - no __setitem__() method
    def __delitem__(self, key):
        "SimpleCAClient Properties keys cannot be removed"        
        raise SimpleCAError('Keys cannot be deleted from ' + \
                            SimpleCAClient.__name__)


    def __getitem__(self, key):

        SimpleCAClient.__name__ + \
        """ behaves as a data dictionary"""
        
        # Check input key
        if key in self.__prop:
            return self.__prop[key]
        else:
            raise SimpleCAClientError("Property with key '%s' not found"%key)

        
    def clear(self):
        raise SimpleCAClientError("Data cannot be cleared from " + \
                                  SimpleCAClient.__name__)
    
    def keys(self):
        return self.__prop.keys()

    def items(self):
        return self.__prop.items()

    def values(self):
        return self.__prop.values()

    def has_key(self):
        return self.__prop.has_key()

    #_________________________________________________________________________
    # End of UserDict derived methods <--


    def setProperties(self, **prop):
        """Update existing properties from an input dictionary
        Check input keys are valid names"""
        
        for key in prop.keys():
            if key not in self.__validKeys:
                raise SimpleCAClientError("Property name \"%s\" is invalid" %\
                                          key)
                
        self.__prop.update(prop)

        

    
    def readProperties(self, propFilePath=None, propElem=None):
        """Read XML properties from a file or cElementTree node

        propFilePath|propElem

        propFilePath: set to read from the specified file
        propElem:     set to read beginning from a cElementTree node"""


        if propFilePath is not None:

            try:
                tree = ElementTree.parse(propFilePath)
            except IOError, e:
                raise MyProxyError(\
                                "Error parsing properties file \"%s\": %s" % \
                                (e.filename, e.strerror))

                propElem = tree.getroot()
                
            except Exception, e:
                raise MyProxyError("Error parsing properties file: %s" % e)

        if propElem is None:
            raise MyProxyError("Root element for parsing is not defined")

        # Get properties from file as a data dictionary
        prop = dict([(elem.tag, elem.text) for elem in propElem])

        # Cut leading and trailing white space apart from pass phrase field
        for key in prop:
            if key != 'xmlSigCertPPhrase': prop[key] = prop[key].strip()

        # Update any existing values        
        self.setProperties(**prop)



     
    def initSrvPx(self):
        """Initialise service proxy"""

        if 'wsdl' not in self.__prop:
            raise SimpleCAClientError("Creating WS proxy: WSDL is not set")
        
        try:
            self.__srvPx = ServiceProxy(self.__prop['wsdl'], use_wsdl=True)
            
        except Exception, e:
            raise SimpleCAClientError("Creating WS proxy: %s" % e)




    def reqCert(self,
                sCertReq=None,
                certReqFilePath=None,
                **prop):        
        """Request certificate from SimpleCA WS"""

        if self.__srvPx is None:
            self.initSrvPx()

        
        # Add to existing properties
        self.setProperties(**prop)

                
        try:
            if sCertReq:
                pass               
            elif certReqFilePath:
                sCertReq = open(certReqFilePath).read()
            else:
                raise Exception("No text or file path input")            
                
        except Exception, e:
            raise SimpleCAClientError(\
                                "Error reading certificate request: %s" % e)  

        try:
            certReq = CertReq(signingKeyFilePath=self.__prop['xmlSigKeyFile'],
                              certFilePathList=self.__prop['xmlSigCertFile'])        
            certReq.sCertReq = sCertReq
            
            # Sign certificate
            certReq.sign(signingKeyPwd=self.__prop['xmlSigCertPPhrase'])
            
        except Exception, e:
            raise SimpleCAClientError(\
                            "Certificate request XML Signature: %s" % e)
        
        
        try:          
            resp = self.__srvPx.reqCert(usrCertReq=certReq.asString())
            if resp['errMsg']:
                raise Exception(resp['errMsg'])

            return resp['usrCert']

        except socket.error, (errNum, errMsg):
            raise SimpleCAClientError("Error making certificate request: %s" %\
                                      errMsg)
            
        except Exception, e:
            raise SimpleCAClientError("Error making certificate request: %s" %\
                                      e)
