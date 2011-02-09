#!/usr/local/NDG/ActivePython-2.4/bin/python

"""Example NDG Security CGI Identity Provider Service

NERC Data Grid Project

P J Kershaw 27/07/06

Copyright (C) 2006 STFC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
import os
from ndg.security.SecurityCGI import IdentityProviderSecurityCGI, SecurityCGIError


class IdPcgi(IdentityProviderSecurityCGI):
    """CGI interface test class for NDG Security Identity Provider service"""

    #_________________________________________________________________________
    def showLogin(self, pageTitle="NDG Login", **kwargs):
        """Display initial NDG login form"""
        super(IdPcgi, self).showLogin(pageTitle=pageTitle, **kwargs)


#_____________________________________________________________________________
if __name__ == "__main__":

    smWSDLuri = "http://gabriel.bnsc.rl.ac.uk/sessionMgr.wsdl"
    smCertFilePath = "/usr/local/NDG/conf/certs/gabriel-sm-cert.pem"

    clntCertFilePath = "../certs/GabrielCGI-cert.pem"
    clntPriKeyFilePath = "../certs/GabrielCGI-key.pem"

    IdPcgi(os.path.basename(__file__),
           smWSDLuri,
           smCertFilePath=smCertFilePath,
           clntCertFilePath=clntCertFilePath,
           clntPriKeyFilePath=clntPriKeyFilePath)()
