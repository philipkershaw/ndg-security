#!/usr/bin/env python
"""Test harness for NDG Certificate Authority client - makes requests for 
issue and revocation of certificates.

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "23/02/06"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

import unittest
import os, sys, getpass
from ConfigParser import SafeConfigParser

from ndg.security.common.ca import CertificateAuthorityClient


class CAClientTestCase(unittest.TestCase):
    
    def setUp(self):
        
        configParser = SafeConfigParser()
        configParser.read("./caClientTest.cfg")
        
        self.cfg = {}
        for section in configParser.sections():
            self.cfg[section] = dict(configParser.items(section))

        tracefile = sys.stderr

        try:
            if self.cfg['setUp'].get('clntprikeypwd') is None:
                clntPriKeyPwd = getpass.getpass(\
                            prompt="\nsetUp - client private key password: ")
            else:
                clntPriKeyPwd = self.cfg['setUp'].get('clntprikeypwd')
        except KeyboardInterrupt:
            sys.exit(0)
            
        # Initialise the Certificate Authority client connection
        # Omit traceFile keyword to leave out SOAP debug info
        self.clnt = CertificateAuthorityClient(uri=self.cfg['setUp']['uri'],
            verifyingCertFilePath=self.cfg['setUp'].get('srvcertfilepath'),
            signingCertFilePath=self.cfg['setUp']['clntcertfilepath'],
            signingPriKeyFilePath=self.cfg['setUp']['clntprikeyfilepath'],
            signingPriKeyPwd=clntPriKeyPwd,
            tracefile=tracefile) 

        self.clnt.openSSLConfig.filePath = \
            os.path.expandvars(self.cfg['setUp'].get('opensslconfigfilepath'))
                
        if self.clnt.openSSLConfig.filePath:
            self.clnt.openSSLConfig.read()
        else:
            self.clnt.openSSLConfig.reqDN = {'O': self.cfg['setUp']['o'],
                                             'OU': self.cfg['setUp']['ou']}


    def test1IssueCert(self):
        """Issue a new certificate"""
        
        cert,priKey = self.clnt.issueCert(CN=self.cfg['test1IssueCert']['cn'])
#        from M2Crypto import X509
#        cert,priKey = self.clnt.issueCert(\
#                      certReq=X509.load_request('tmp-cert_request.pem.alt'))
        print "Issuing new cert '%s'" % self.cfg['test1IssueCert']['cn']
        

    def test2RevokeCert(self):
        """test2RevokeCert: revoke a certificate"""

        self.clnt.revokeCert(self.cfg['test2RevokeCert']['revokeCert'])

        self.sessCookie = SessionCookie(cookie)
        print "User '%s' connected to Certificate Authority:\n%s" % \
            (self.cfg['test2RevokeCert']['username'], self.sessCookie)
            

    def test3GetCRL(self):
        """test3GetCRL: get Certificate Revocation List"""

        passphrase = self.cfg['test3GetCRL'].get('passphrase') or \
            getpass.getpass(\
                    prompt="\ntest3GetCRL pass-phrase for user: ")

        crl = self.clnt.getCRL()
        print "CRL:\n%s" % crl
            
            
            
#_____________________________________________________________________________       
class CAClientTestSuite(unittest.TestSuite):
    
    def __init__(self):
        map = map(CAClientTestCase,
                  (
                    "test1IssueCert",
                    "test2RevokeCert",
                    "test3GetCRL",
                  ))
        unittest.TestSuite.__init__(self, map)
            
                                                    
if __name__ == "__main__":
    unittest.main()        
