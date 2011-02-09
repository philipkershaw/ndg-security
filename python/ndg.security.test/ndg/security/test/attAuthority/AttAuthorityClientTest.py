#!/usr/bin/env python
"""NDG Attribute Authority SOAP client unit tests

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "05/05/05, major update 16/01/07"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

import unittest
import os, sys, getpass, re
from ConfigParser import SafeConfigParser

from ndg.security.common.AttAuthority import AttAuthorityClient
from ndg.security.common.AttCert import AttCertRead
from ndg.security.common.X509 import X509CertParse, X509CertRead
from ndg.security.common.wsSecurity import SignatureHandler as SigHdlr

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_AACLNT_UNITTEST_DIR'], file)


class AttAuthorityClientTestCase(unittest.TestCase):
    clntPriKeyPwd = None
    pemPat = "-----BEGIN CERTIFICATE-----[^\-]*-----END CERTIFICATE-----"

    def _getCertChainFromProxyCertFile(self, proxyCertFilePath):
        '''Read proxy cert and user cert from a single PEM file and put in
        a list ready for input into SignatureHandler'''               
        proxyCertFileTxt = open(proxyCertFilePath).read()
        
        pemPatRE = re.compile(self.__class__.pemPat, re.S)
        x509CertList = pemPatRE.findall(proxyCertFileTxt)
        
        signingCertChain = [X509CertParse(x509Cert) for x509Cert in \
                            x509CertList]
    
        # Expecting proxy cert first - move this to the end.  This will
        # be the cert used to verify the message signature
        signingCertChain.reverse()
        
        return signingCertChain


    def setUp(self):

        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_AACLNT_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_AACLNT_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))

        configParser = SafeConfigParser()
        configFilePath = jnPath(os.environ['NDGSEC_AACLNT_UNITTEST_DIR'],
                                'attAuthorityClientTest.cfg')
        configParser.read(configFilePath)
        
        self.cfg = {}
        for section in configParser.sections():
            self.cfg[section] = dict(configParser.items(section))

        tracefile = sys.stderr

        if self.clntPriKeyPwd is None:
            try:
                if self.cfg['setUp'].get('clntprikeypwd') is None:
                    self.clntPriKeyPwd = getpass.getpass(\
                            prompt="\nsetUp - client private key password: ")
                else:
                    self.clntPriKeyPwd=self.cfg['setUp'].get('clntprikeypwd')
            except KeyboardInterrupt:
                sys.exit(0)

        # List of CA certificates for use in validation of certs used in
        # signature for server reponse
        try:
            caCertFilePathList = [xpdVars(file) for file in \
                            self.cfg['setUp']['cacertfilepathlist'].split()]
        except KeyError:
            caCertFilePathList = []
          
        try:
            sslCACertList = [X509CertRead(xpdVars(file)) for file in \
                         self.cfg['setUp']['sslcacertfilepathlist'].split()]
        except KeyError:
            sslCACertList = []
            
        clntCertFilePath = xpdVars(self.cfg['setUp'].get('clntcertfilepath'))         
        clntPriKeyFilePath=xpdVars(self.cfg['setUp'].get('clntprikeyfilepath'))
        reqBinSecTokValType = self.cfg['setUp'].get('reqbinsectokvaltype')

        # Check certificate types proxy or standard
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

        # Instantiate WS proxy
        self.clnt = AttAuthorityClient(uri=self.cfg['setUp']['uri'],
                        sslPeerCertCN=self.cfg['setUp'].get('sslpeercertcn'),
                        sslCACertList=sslCACertList,
                        setSignatureHandler=setSignatureHandler,
                        reqBinSecTokValType=reqBinSecTokValType,
                        signingCertFilePath=signingCertFilePath,
                        signingCertChain=signingCertChain,
                        signingPriKeyFilePath=clntPriKeyFilePath,
                        signingPriKeyPwd=self.clntPriKeyPwd,
                        caCertFilePathList=caCertFilePathList,
                        refC14nKw=refC14nKw,
                        signedInfoC14nKw=signedInfoC14nKw,
                        tracefile=sys.stderr)
            
    
    def test1GetX509Cert(self):
        '''test1GetX509Cert: retrieve Attribute Authority's X.509 cert.'''
        resp = self.clnt.getX509Cert()
        print "Attribute Authority X.509 cert.:\n" + resp

    def test2GetHostInfo(self):
        """test2GetHostInfo: retrieve info for AA host"""
        hostInfo = self.clnt.getHostInfo()
        print "Host Info:\n %s" % hostInfo
        

    def test3GetTrustedHostInfo(self):
        """test3GetTrustedHostInfo: retrieve trusted host info matching a
        given role"""
        trustedHostInfo = self.clnt.getTrustedHostInfo(\
                                 self.cfg['test3GetTrustedHostInfo']['role'])
        for hostname, hostInfo in trustedHostInfo.items():
            assert hostname, "Hostname not set"
            for k, v in hostInfo.items():
                assert k, "hostInfo value key unset"

        print "Trusted Host Info:\n %s" % trustedHostInfo


    def test4GetTrustedHostInfoWithNoRole(self):
        """test4GetTrustedHostInfoWithNoRole: retrieve trusted host info 
        irrespective of role"""
        trustedHostInfo = self.clnt.getTrustedHostInfo()
        for hostname, hostInfo in trustedHostInfo.items():
            assert hostname, "Hostname not set"
            for k, v in hostInfo.items():
                assert k, "hostInfo value key unset"
                assert v, ("%s value not set" % k)
                   
        print "Trusted Host Info:\n %s" % trustedHostInfo
        

    def test4aGetAllHostsInfo(self):
        """test4aGetAllHostsInfo: retrieve info for all hosts"""
        allHostInfo = self.clnt.getAllHostsInfo()
        for hostname, hostInfo in allHostInfo.items():
            assert hostname, "Hostname not set"
            for k, v in hostInfo.items():
                assert k, "hostInfo value key unset"
                   
        print "All Hosts Info:\n %s" % allHostInfo


    def test5GetAttCert(self):        
        """test5GetAttCert: Request attribute certificate from NDG Attribute 
        Authority Web Service."""
    
        # Read user Certificate into a string ready for passing via WS
        try:
            userCertFilePath = \
            xpdVars(self.cfg['test5GetAttCert'].get('issuingclntcertfilepath'))
            userCertTxt = open(userCertFilePath, 'r').read()
        
        except TypeError:
            # No issuing cert set
            userCertTxt = None
                
        except IOError, ioErr:
            raise "Error reading certificate file \"%s\": %s" % \
                                    (ioErr.filename, ioErr.strerror)

        # Make attribute certificate request
        attCert = self.clnt.getAttCert(userCert=userCertTxt)
        
        print "Attribute Certificate: \n\n:" + str(attCert)
        
        attCert.filePath = \
                        xpdVars(self.cfg['test5GetAttCert']['attcertfilepath'])
        attCert.write()
        
        
    def test6GetAttCertWithUserIdSet(self):        
        """test6GetAttCertWithUserIdSet: Request attribute certificate from 
        NDG Attribute Authority Web Service setting a specific user Id 
        independent of the signer of the SOAP request."""
    
        # Read user Certificate into a string ready for passing via WS
        try:
            userCertFilePath = xpdVars(\
    self.cfg['test6GetAttCertWithUserIdSet'].get('issuingclntcertfilepath'))
            userCertTxt = open(userCertFilePath, 'r').read()
        
        except TypeError:
            # No issuing cert set
            userCertTxt = None
                
        except IOError, ioErr:
            raise "Error reading certificate file \"%s\": %s" % \
                                    (ioErr.filename, ioErr.strerror)

        # Make attribute certificate request
        userId = self.cfg['test6GetAttCertWithUserIdSet']['userid']
        attCert = self.clnt.getAttCert(userId=userId,
                                       userCert=userCertTxt)
        
        print "Attribute Certificate: \n\n:" + str(attCert)
        
        attCert.filePath = \
                        xpdVars(self.cfg['test5GetAttCert']['attcertfilepath'])
        attCert.write()


    def test7GetMappedAttCert(self):        
        """test7GetMappedAttCert: Request mapped attribute certificate from 
        NDG Attribute Authority Web Service."""
    
        # Read user Certificate into a string ready for passing via WS
        try:
            userCertFilePath = xpdVars(\
            self.cfg['test7GetMappedAttCert'].get('issuingclntcertfilepath'))
            userCertTxt = open(userCertFilePath, 'r').read()
        
        except TypeError:
            # No issuing cert set
            userCertTxt = None
                
        except IOError, ioErr:
            raise "Error reading certificate file \"%s\": %s" % \
                                    (ioErr.filename, ioErr.strerror)
    
    
        # Simlarly for Attribute Certificate 
        try:
            userAttCert = AttCertRead(xpdVars(\
                self.cfg['test7GetMappedAttCert']['userattcertfilepath']))
            
        except IOError, ioErr:
            raise "Error reading attribute certificate file \"%s\": %s" %\
                                    (ioErr.filename, ioErr.strerror)

        try:
            if self.cfg['test7GetMappedAttCert'].get('clntprikeypwd') is None:
                clntPriKeyPwd = getpass.getpass(\
                            prompt="\nsetUp - client private key password: ")
            else:
                clntPriKeyPwd = \
                        self.cfg['test7GetMappedAttCert'].get('clntprikeypwd')
        except KeyboardInterrupt:
            sys.exit(0)

        # List of CA certificates for use in validation of certs used in
        # signature for server reponse
        try:
            caCertFilePathList = [xpdVars(file) for file in \
            self.cfg['test7GetMappedAttCert']['cacertfilepathlist'].split()]
        except:
            caCertFilePathList = []
            
            
        clntCertFilePath = xpdVars(\
                self.cfg['test7GetMappedAttCert'].get('clntcertfilepath'))
        clntPriKeyFilePath = xpdVars(\
                self.cfg['test7GetMappedAttCert'].get('clntprikeyfilepath'))
                
        reqBinSecTokValType = \
                self.cfg['test7GetMappedAttCert'].get('reqbinsectokvaltype')

        # Check certificate types proxy or standard
        if reqBinSecTokValType == SigHdlr.binSecTokValType["X509PKIPathv1"]:
            signingCertChain = \
                        self._getCertChainFromProxyCertFile(clntCertFilePath)
            signingCertFilePath = None
        else:
            signingCertChain = None
            signingCertFilePath = clntCertFilePath

        setSignatureHandler = \
                eval(self.cfg['test7GetMappedAttCert']['setsignaturehandler'])
        
        # Make client to site B Attribute Authority
        clnt = AttAuthorityClient(\
                                uri=self.cfg['test7GetMappedAttCert']['uri'], 
                                setSignatureHandler=setSignatureHandler,
                                reqBinSecTokValType=reqBinSecTokValType,
                                signingCertFilePath=signingCertFilePath,
                                signingCertChain=signingCertChain,
                                signingPriKeyFilePath=clntPriKeyFilePath,
                                signingPriKeyPwd=clntPriKeyPwd,
                                caCertFilePathList=caCertFilePathList,
                                tracefile=sys.stderr)
    
        # Make attribute certificate request
        attCert = clnt.getAttCert(userCert=userCertTxt,
                                  userAttCert=userAttCert)
        print "Attribute Certificate: \n\n:" + str(attCert)
        
        attCert.filePath = xpdVars(\
                    self.cfg['test7GetMappedAttCert']['mappedattcertfilepath'])
        attCert.write()
        
        
    def test8GetMappedAttCertStressTest(self):        
        """test8GetMappedAttCertStressTest: Request mapped attribute 
        certificate from NDG Attribute Authority Web Service."""
    
        # Read user Certificate into a string ready for passing via WS
        try:
            userCertFilePath = xpdVars(\
    self.cfg['test8GetMappedAttCertStressTest'].get('issuingclntcertfilepath'))
            userCertTxt = open(userCertFilePath, 'r').read()
        
        except TypeError:
            # No issuing cert set
            userCertTxt = None
                
        except IOError, ioErr:
            raise "Error reading certificate file \"%s\": %s" % \
                                    (ioErr.filename, ioErr.strerror)

        try:
            clntPriKeyPwd = \
            self.cfg['test8GetMappedAttCertStressTest'].get('clntprikeypwd')
            if clntPriKeyPwd is None:
                clntPriKeyPwd = getpass.getpass(\
                            prompt="\nsetUp - client private key password: ")
        except KeyboardInterrupt:
            sys.exit(0)

        # List of CA certificates for use in validation of certs used in
        # signature for server reponse
        try:
            caCertFilePathList = [xpdVars(file) for file in \
    self.cfg['test8GetMappedAttCertStressTest']['cacertfilepathlist'].split()]
        except:
            caCertFilePathList = []


        clntCertFilePath = xpdVars(\
        self.cfg['test8GetMappedAttCertStressTest'].get('clntcertfilepath'))           

        clntPriKeyFilePath = xpdVars(\
        self.cfg['test8GetMappedAttCertStressTest'].get('clntprikeyfilepath'))

        reqBinSecTokValType = \
        self.cfg['test8GetMappedAttCertStressTest'].get('reqbinsectokvaltype')
        
        # Check certificate types proxy or standard
        if reqBinSecTokValType == SigHdlr.binSecTokValType["X509PKIPathv1"]:
            signingCertChain = \
                        self._getCertChainFromProxyCertFile(clntCertFilePath)
            signingCertFilePath = None
        else:
            signingCertChain = None
            signingCertFilePath = clntCertFilePath

        setSignatureHandler = \
    eval(self.cfg['test8GetMappedAttCertStressTest']['setsignaturehandler'])
        
        # Make client to site B Attribute Authority
        clnt = AttAuthorityClient(\
                        uri=self.cfg['test8GetMappedAttCertStressTest']['uri'], 
                        setSignatureHandler=setSignatureHandler,
                        reqBinSecTokValType=reqBinSecTokValType,
                        signingCertChain=signingCertChain,
                        signingCertFilePath=clntCertFilePath,
                        signingPriKeyFilePath=clntPriKeyFilePath,
                        signingPriKeyPwd=clntPriKeyPwd,
                        caCertFilePathList=caCertFilePathList,
                        tracefile=sys.stderr)

        acFilePathList = [xpdVars(file) for file in \
self.cfg['test8GetMappedAttCertStressTest']['userattcertfilepathlist'].split()]

        for acFilePath in acFilePathList:
            try:
                userAttCert = AttCertRead(acFilePath)
                
            except IOError, ioErr:
                raise "Error reading attribute certificate file \"%s\": %s" %\
                                        (ioErr.filename, ioErr.strerror)
        
            # Make attribute certificate request
            try:
                attCert = clnt.getAttCert(userCert=userCertTxt,
                                          userAttCert=userAttCert)
            except Exception, e:
                outFilePfx = 'test8GetMappedAttCertStressTest-%s' % \
                        os.path.basename(acFilePath)    
                msgFile = open(outFilePfx+".msg", 'w')
                msgFile.write('Failed for "%s": %s\n' % (acFilePath, e))
             
             
#_____________________________________________________________________________       
class AttAuthorityClientTestSuite(unittest.TestSuite):
    def __init__(self):
        map = map(AttAuthorityClientTestCase,
                  (
                    "test1GetX509Cert",
                    "test2GetHostInfo",
                    "test3GetTrustedHostInfo",
                    "test4GetTrustedHostInfoWithNoRole",
                    "test5GetAttCert",
                    "test6GetAttCertWithUserIdSet",
                    "test7GetMappedAttCert",
                    "test8GetMappedAttCertStressTest",
                  ))
        unittest.TestSuite.__init__(self, map)
                                        
if __name__ == "__main__":
    unittest.main()
