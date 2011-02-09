#!/usr/local/NDG/ActivePython-2.4/bin/python

"""Example NDG Security CGI Service Provider Id Request Service

NERC Data Grid Project

P J Kershaw 27/07/06

Copyright (C) 2006 STFC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
import os
from ndg.security.SecurityCGI import ServiceProviderSecurityCGI, SecurityCGIError


class SPcgi(ServiceProviderSecurityCGI):
    """CGI interface test class for NDG Security Service Provider requesting
    user ID from an NDG Identity Provider"""

    #_________________________________________________________________________
    def showIdPsiteSelect(self, 
               pageTitle='Select your home site to retrieve your credentials',
               **kwargs):

        super(SPcgi, self).showIdPsiteSelect(pageTitle=pageTitle, **kwargs)


    #_________________________________________________________________________
    def onCredsSet(self,
                   sessCookie=None,
				   pageTitle='Credentials returned from IdP',
                   bodyTxt='<h2>NDG Security Cookie is present</h2>'):
        
        super(SPcgi, self).onCredsSet(sessCookie=sessCookie,
                                      pageTitle=pageTitle,
                                      bodyTxt=bodyTxt)


#_____________________________________________________________________________
if __name__ == "__main__":

    returnURI = 'https://gabriel.bnsc.rl.ac.uk/cgi-bin/sp.py'
    aaWSDL = 'http://gabriel.bnsc.rl.ac.uk/attAuthority.wsdl'
    aaCertFilePath = "/usr/local/NDG/conf/certs/gabriel-aa-cert.pem"

    clntCertFilePath = "../certs/GabrielCGI-cert.pem"
    clntPriKeyFilePath = "../certs/GabrielCGI-key.pem"

    SPcgi(os.path.basename(__file__),
          returnURI,
          aaWSDL,
          aaCertFilePath=aaCertFilePath,
          clntCertFilePath=clntCertFilePath,
          clntPriKeyFilePath=clntPriKeyFilePath)()

