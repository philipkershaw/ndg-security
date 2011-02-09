#!/usr/bin/env python
"""Test harness for NDG Session Manager client - makes requests for 
authentication and authorisation.  An Attribute Authority and Simple CA
services must be running for the reqAuthorisation and addUser tests

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
import os, sys, getpass, re
from ConfigParser import SafeConfigParser

from ndg.security.common.SessionMgr import SessionMgrClient, \
    AttributeRequestDenied
    
from ndg.security.common.X509 import X509CertParse, X509CertRead
from ndg.security.common.wsSecurity import SignatureHandler as SigHdlr

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_SMCLNT_UNITTEST_DIR'], file)


class SessionMgrClientTestCase(unittest.TestCase):
    pemPat = "-----BEGIN CERTIFICATE-----[^\-]*-----END CERTIFICATE-----"
        
    test2Passphrase = None
    test3Passphrase = None

    def _getCertChainFromProxyCertFile(self, certChainFilePath):
        '''Read user cert and user cert from a single PEM file and put in
        a list ready for input into SignatureHandler'''               
        certChainFileTxt = open(certChainFilePath).read()
        
        pemPatRE = re.compile(self.__class__.pemPat, re.S)
        x509CertList = pemPatRE.findall(certChainFileTxt)
        
        signingCertChain = [X509CertParse(x509Cert) for x509Cert in \
                            x509CertList]
    
        # Expecting user cert first - move this to the end.  This will
        # be the cert used to verify the message signature
        signingCertChain.reverse()
        
        return signingCertChain


    def setUp(self):
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_SMCLNT_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_SMCLNT_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))
        
        configParser = SafeConfigParser()
        configFilePath = jnPath(os.environ['NDGSEC_SMCLNT_UNITTEST_DIR'],
                                "sessionMgrClientTest.cfg")
        configParser.read(configFilePath)
        
        self.cfg = {}
        for section in configParser.sections():
            self.cfg[section] = dict(configParser.items(section))

        try:
            if self.cfg['setUp'].get('clntprikeypwd') is None:
                clntPriKeyPwd = getpass.getpass(\
                            prompt="\nsetUp - client private key password: ")
            else:
                clntPriKeyPwd = self.cfg['setUp'].get('clntprikeypwd')
        except KeyboardInterrupt:
            sys.exit(0)

        # List of CA certificates for use in validation of certs used in
        # signature for server reponse
        try:
            caCertFilePathList = [xpdVars(file) for file in \
                            self.cfg['setUp']['cacertfilepathlist'].split()]
        except:
            caCertFilePathList = []
          
        try:
            sslCACertList = [X509CertRead(xpdVars(file)) for file in \
                         self.cfg['setUp']['sslcacertfilepathlist'].split()]
        except KeyError:
            sslCACertList = []
          
        clntCertFilePath = xpdVars(self.cfg['setUp']['clntcertfilepath'])
        clntPriKeyFilePath = xpdVars(self.cfg['setUp']['clntprikeyfilepath'])
        
        reqBinSecTokValType = self.cfg['setUp'].get('reqbinsectokvaltype')

        # Set format for certificate(s) to be included in client SOAP messages
        # to enable the Session Manager server to verify messages.
        if reqBinSecTokValType == SigHdlr.binSecTokValType["X509PKIPathv1"]:
            signingCertChain = \
                        self._getCertChainFromProxyCertFile(clntCertFilePath)
            signingCertFilePath = None
        else:
            signingCertChain = None
            signingCertFilePath = clntCertFilePath

        # Inclusive namespace prefixes for Exclusive C14N
        try:
            refC14nKw = {'unsuppressedPrefixes':
                         self.cfg['setUp']['wssrefinclns'].split()}           
        except KeyError:
            refC14nKw = {'unsuppressedPrefixes':[]}

        try:
            signedInfoC14nKw = {'unsuppressedPrefixes':
                            self.cfg['setUp']['wsssignedinfoinclns'].split()}          
        except KeyError:
            signedInfoC14nKw = {'unsuppressedPrefixes':[]}
                
        setSignatureHandler = eval(self.cfg['setUp']['setsignaturehandler'])
            
        # Initialise the Session Manager client connection
        # Omit traceFile keyword to leave out SOAP debug info
        self.clnt = SessionMgrClient(uri=self.cfg['setUp']['smuri'],
                        sslCACertList=sslCACertList,
                        sslPeerCertCN=self.cfg['setUp'].get('sslpeercertcn'),
                        setSignatureHandler=setSignatureHandler,
                        reqBinSecTokValType=reqBinSecTokValType,
                        signingCertFilePath=clntCertFilePath,
                        signingCertChain=signingCertChain,
                        signingPriKeyFilePath=clntPriKeyFilePath,
                        signingPriKeyPwd=clntPriKeyPwd,
                        caCertFilePathList=caCertFilePathList,
                        refC14nKw=refC14nKw,
                        signedInfoC14nKw=signedInfoC14nKw,
                        tracefile=sys.stderr) 
        
        self.sessID = None
        self.userCert = None
        self.userPriKey = None
        self.issuingCert = None
        

    def test1Connect(self):
        """test1Connect: Connect as if acting as a browser client - 
        a session ID is returned"""
        
        username = self.cfg['test1Connect']['username']
        
        if self.__class__.test2Passphrase is None:
            self.__class__.test2Passphrase = \
                                    self.cfg['test1Connect'].get('passphrase')
        
        if not self.__class__.test2Passphrase:
            self.__class__.test2Passphrase = getpass.getpass(\
                prompt="\ntest1Connect pass-phrase for user %s: " % username)

        self.userCert, self.userPriKey, self.issuingCert, self.sessID = \
            self.clnt.connect(self.cfg['test1Connect']['username'], 
                              passphrase=self.__class__.test2Passphrase)

        print "User '%s' connected to Session Manager:\n%s" % \
                                                        (username, self.sessID)
            
        creds='\n'.join((self.issuingCert or '',self.userCert,self.userPriKey))
        open(mkPath("user.creds"), "w").write(creds)
            
            
    def test2GetSessionStatus(self):
        """test2GetSessionStatus: check a session is alive"""
        print "\n\t" + self.test2GetSessionStatus.__doc__
        
        self.test1Connect()
        assert self.clnt.getSessionStatus(sessID=self.sessID), \
                "Session is dead"
                
        print "User connected to Session Manager with sessID=%s" % self.sessID

        assert not self.clnt.getSessionStatus(sessID='abc'), \
            "sessID=abc shouldn't exist!"
            
        print "CORRECT: sessID=abc doesn't exist"


    def test3ConnectNoCreateServerSess(self):
        """test3ConnectNoCreateServerSess: Connect as a non browser client - 
        sessID should be None"""

        username = self.cfg['test3ConnectNoCreateServerSess']['username']
        
        if self.__class__.test3Passphrase is None:
            self.__class__.test3Passphrase = \
                self.cfg['test3ConnectNoCreateServerSess'].get('passphrase')
                
        if not self.__class__.test3Passphrase:
            prompt="\ntest3ConnectNoCreateServerSess pass-phrase for user %s: "
            self.__class__.test3Passphrase = getpass.getpass(\
                                                    prompt=prompt % username)
            
        self.userCert, self.userPriKey, self.issuingCert, sessID = \
            self.clnt.connect(username, 
                              passphrase=self.__class__.test3Passphrase,
                              createServerSess=False)
        
        # Expect null session ID
        assert(not sessID)
          
        print "User '%s' retrieved creds. from Session Manager:\n%s" % \
                                                    (username, self.userCert)
            

    def test4DisconnectWithSessID(self):
        """test4DisconnectWithSessID: disconnect as if acting as a browser client 
        """
        
        print "\n\t" + self.test4DisconnectWithSessID.__doc__
        self.test1Connect()
        
        self.clnt.disconnect(sessID=self.sessID)
        
        print "User disconnected from Session Manager:\n%s" % self.sessID
            

    def test5DisconnectWithUserCert(self):
        """test5DisconnectWithUserCert: Disconnect as a command line client 
        """
        
        print "\n\t" + self.test5DisconnectWithUserCert.__doc__
        self.test1Connect()
        
        # Use user cert / private key just obtained from connect call for
        # signature generation
        if self.issuingCert:
            self.clnt.signatureHandler.reqBinSecTokValType = 'X509PKIPathv1'
            self.clnt.signatureHandler.signingPriKey = self.userPriKey        
            self.clnt.signatureHandler.signingCertChain = (self.issuingCert,
                                                           self.userCert)
            self.clnt.signatureHandler.signingCert = None
        else:
            self.clnt.signatureHandler.reqBinSecTokValType = 'X509v3'
            self.clnt.signatureHandler.signingPriKey = self.userPriKey        
            self.clnt.signatureHandler.signingCertChain = ()
            self.clnt.signatureHandler.signingCert = self.userCert
            
        # Proxy cert in signature determines ID of session to
        # delete
        self.clnt.disconnect()
        print "User disconnected from Session Manager:\n%s" % self.userCert


    def test6GetAttCertWithSessID(self):
        """test6GetAttCertWithSessID: make an attribute request using
        a session ID as authentication credential"""

        print "\n\t" + self.test6GetAttCertWithSessID.__doc__        
        self.test1Connect()
        
        attCert = self.clnt.getAttCert(\
            sessID=self.sessID, 
            attAuthorityURI=self.cfg['test6GetAttCertWithSessID']['aauri'])
        
        print "Attribute Certificate:\n%s" % attCert 
        attCert.filePath = \
            xpdVars(self.cfg['test6GetAttCertWithSessID']['acoutfilepath']) 
        attCert.write()


    def test6aGetAttCertRefusedWithSessID(self):
        """test6aGetAttCertRefusedWithSessID: make an attribute request using
        a sessID as authentication credential requesting an AC from an
        Attribute Authority where the user is NOT registered"""

        print "\n\t" + self.test6aGetAttCertRefusedWithSessID.__doc__        
        self.test1Connect()
        
        aaURI = self.cfg['test6aGetAttCertRefusedWithSessID']['aauri']
        
        try:
            attCert = self.clnt.getAttCert(sessID=self.sessID, 
                                           attAuthorityURI=aaURI,
                                           mapFromTrustedHosts=False)
        except AttributeRequestDenied, e:
            print "SUCCESS - obtained expected result: %s" % e
            return
        
        self.fail("Request allowed from AA where user is NOT registered!")


    def test6bGetMappedAttCertWithSessID(self):
        """test6bGetMappedAttCertWithSessID: make an attribute request using
        a session ID as authentication credential"""

        print "\n\t" + self.test6bGetMappedAttCertWithSessID.__doc__        
        self.test1Connect()
        
        aaURI = self.cfg['test6bGetMappedAttCertWithSessID']['aauri']
        
        attCert=self.clnt.getAttCert(sessID=self.sessID,attAuthorityURI=aaURI)
        
        print "Attribute Certificate:\n%s" % attCert  


    def test6cGetAttCertWithExtAttCertListWithSessID(self):
        """test6cGetAttCertWithSessID: make an attribute request using
        a session ID as authentication credential"""
        
        print "\n\t" + \
            self.test6cGetAttCertWithExtAttCertListWithSessID.__doc__        
        self.test1Connect()
        
        aaURI = \
            self.cfg['test6cGetAttCertWithExtAttCertListWithSessID']['aauri']
        
        # Use output from test6GetAttCertWithSessID!
        extACFilePath = xpdVars(\
    self.cfg['test6cGetAttCertWithExtAttCertListWithSessID']['extacfilepath'])
        extAttCert = open(extACFilePath).read()
        
        attCert = self.clnt.getAttCert(sessID=self.sessID, 
                                       attAuthorityURI=aaURI,
                                       extAttCertList=[extAttCert])
          
        print "Attribute Certificate:\n%s" % attCert  


    def test7GetAttCertWithUserCert(self):
        """test7GetAttCertWithUserCert: make an attribute request using
        a user cert as authentication credential"""
        print "\n\t" + self.test7GetAttCertWithUserCert.__doc__
        self.test1Connect()

        if self.issuingCert:
            self.clnt.signatureHandler.reqBinSecTokValType = 'X509PKIPathv1'
            self.clnt.signatureHandler.signingPriKey = self.userPriKey        
            self.clnt.signatureHandler.signingCertChain = (self.issuingCert,
                                                           self.userCert)
            self.clnt.signatureHandler.signingCert = None
        else:
            self.clnt.signatureHandler.reqBinSecTokValType = 'X509v3'
            self.clnt.signatureHandler.signingPriKey = self.userPriKey        
            self.clnt.signatureHandler.signingCertChain = ()
            self.clnt.signatureHandler.signingCert = self.userCert
        
        # Request an attribute certificate from an Attribute Authority 
        # using the userCert returned from connect()
        
        aaURI = self.cfg['test7GetAttCertWithUserCert']['aauri']
        attCert = self.clnt.getAttCert(attAuthorityURI=aaURI)
          
        print "Attribute Certificate:\n%s" % attCert  


    def test8GetX509Cert(self):
        "test8GetX509Cert: return the Session Manager's X.509 Cert."
        cert = self.clnt.getX509Cert()
                                             
        print "Session Manager X.509 Certificate:\n" + cert
            
            
#_____________________________________________________________________________       
class SessionMgrClientTestSuite(unittest.TestSuite):
    
    def __init__(self):
        map = map(SessionMgrClientTestCase,
                  (
                    "test1Connect",
                    "test2GetSessionStatus",
                    "test3ConnectNoCreateServerSess",
                    "test4DisconnectWithSessID",
                    "test5DisconnectWithUserCert",
                    "test6GetAttCertWithSessID",
                    "test6bGetMappedAttCertWithSessID",
                    "test6cGetAttCertWithExtAttCertListWithSessID",
                    "test7GetAttCertWithUserCert",
                    "test8GetX509Cert",
                  ))
        unittest.TestSuite.__init__(self, map)
            
                                                    
if __name__ == "__main__":
    unittest.main()        
