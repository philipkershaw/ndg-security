#!/usr/bin/env python

"""NDG Attribute Authority client - makes requests for authorisation

NERC Data Grid Project

P J Kershaw 05/05/05

Copyright (C) 2006 STFC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

__revision__ = '$Id$'

from ZSI import ServiceProxy
import sys

from ndg.security.X509 import *


def reqAuthorisation():
    
    """Request authorisation from NDG Attribute Authority Web Service."""

    # Attribute Authority WSDL
    aaWSDL = './attAuthority.wsdl'
    
    # User's proxy certificate
    usrProxyCertFilePath = "./certs/pjkproxy.pem"

    # Existing Attribute Certificate held in user's CredentialWallet.  This is
    # available for use with trusted data centres to make new mapped Attribute
    # Certificates
    usrAttCertFilePath = "./attCert/attCert-pjk-BADC.xml"

    # Make Attribute Authority raise an exception
    #usrAttCertFilePath = "attCert-tampered.xml"


    print "Requesting authorisation for user cert file: \"%s\"" % \
          usrProxyCertFilePath


    # Read user Proxy Certificate into a string ready for passing via WS
    try:
        usrProxyCertFileTxt = open(usrProxyCertFilePath, 'r').read()
        
    except IOError, ioErr:
        raise "Error reading proxy certificate file \"%s\": %s" % \
                                (ioErr.filename, ioErr.strerror)


    # Simlarly for Attribute Certificate if present ...
    if usrAttCertFilePath is not None:
        
        try:
            usrAttCertFileTxt = open(usrAttCertFilePath, 'r').read()
            
        except IOError, ioErr:
            raise "Error reading attribute certificate file \"%s\": %s" % \
                                    (ioErr.filename, ioErr.strerror)
    else:
        usrAttCertFileTxt = None


    # Instantiate WS proxy
    aaSrv = ServiceProxy(aaWSDL, use_wsdl=True)
        

    # Make authorsation request
    try:   
        resp = aaSrv.reqAuthorisation(usrProxyCert=usrProxyCertFileTxt,
                                      usrAttCert=usrAttCertFileTxt)
        if resp['errMsg']:
            raise Exception(resp['errMsg'])
        
        return resp['attCert']
        
    except Exception, excep:
        print "Error: %s" % str(excep)
    


if __name__ == '__main__':
    
    print reqAuthorisation()
