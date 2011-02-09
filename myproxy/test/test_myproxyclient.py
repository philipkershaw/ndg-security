#!/usr/bin/env python
"""MyProxy Client unit tests

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "02/07/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = """BSD- See LICENSE file in top-level directory"""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)

import unittest
import os
import sys
import getpass
import traceback
from os import path

from OpenSSL import crypto

from myproxy.client import CaseSensitiveConfigParser, MyProxyClient

mkPath = lambda file: path.join(os.environ['MYPROXYCLIENT_UNITTEST_DIR'], file)

class _MyProxyClientTestCase(unittest.TestCase):
    '''Base implements environment settings common to all test case classes'''
    if 'NDGSEC_INT_DEBUG' in os.environ:
        import pdb
        pdb.set_trace()
    
    if 'MYPROXYCLIENT_UNITTEST_DIR' not in os.environ:
        os.environ['MYPROXYCLIENT_UNITTEST_DIR'] = \
                                        path.abspath(path.dirname(__file__))


class MyProxyClientLiveTestCase(_MyProxyClientTestCase):
    '''Tests require a connection to a real MyProxy service running on a host
    '''
    CONFIG_FILENAME = "myProxyClientTest.cfg"
    
    def setUp(self):
        
        super(MyProxyClientLiveTestCase, self).setUp()
        
        configParser = CaseSensitiveConfigParser()
        configFilePath = path.join(os.environ['MYPROXYCLIENT_UNITTEST_DIR'],
                                   MyProxyClientLiveTestCase.CONFIG_FILENAME)
        configParser.read(configFilePath)
        
        self.cfg = {}
        for section in configParser.sections():
            self.cfg[section] = dict(configParser.items(section))
        
        configFilePath = path.expandvars(self.cfg['setUp']['cfgFilePath'])
        self.clnt = MyProxyClient(cfgFilePath=configFilePath)
        
    def test01Store(self):
        # upload X509 cert and private key to repository
        thisSection = self.cfg['test01Store']
        
        passphrase = thisSection.get('passphrase')
        if passphrase is None:
            passphrase = getpass.getpass(prompt="\ntest1Store credential "
                                                "pass-phrase: ")
            
        sslKeyFilePassphrase = thisSection.get('sslKeyFilePassphrase')
        if sslKeyFilePassphrase is None:
            sslKeyFilePassphrase = getpass.getpass(
                        prompt="\ntest1Store credential owner pass-phrase: ")

        certFile = path.expandvars(thisSection['ownerCertFile'])
        keyFile = path.expandvars(thisSection['ownerKeyFile'])
        sslCertFile = path.expandvars(thisSection['sslCertFile'])
        sslKeyFile = path.expandvars(thisSection['sslKeyFile'])
            
        self.clnt.store(thisSection['username'],
                        passphrase,
                        certFile,
                        keyFile,
                        sslCertFile=sslCertFile,
                        sslKeyFile=sslKeyFile,
                        sslKeyFilePassphrase=sslKeyFilePassphrase,
                        force=False)
        print("Store creds for user %s" % thisSection['username'])
    
    def test02GetDelegation(self):
        # retrieve proxy cert./private key
        thisSection = self.cfg['test02GetDelegation']
        
        passphrase = thisSection.get('passphrase')
        if passphrase is None:
            passphrase = getpass.getpass(prompt="\ntest2GetDelegation "
                                                "passphrase: ")
         
        proxyCertFile = path.expandvars(thisSection['proxyCertFileOut'])
        proxyKeyFile = path.expandvars(thisSection['proxyKeyFileOut'])

        creds = self.clnt.getDelegation(thisSection['username'], passphrase)
        print "proxy credentials:" 
        print ''.join(creds)
        open(proxyCertFile, 'w').write(creds[0]+''.join(creds[2:]))
        open(proxyKeyFile, 'w').write(creds[1])

    def test03Info(self):
        # Retrieve information about a given credential
        thisSection = self.cfg['test03Info']
        
        # sslKeyFilePassphrase can be omitted from the congif file in which case
        # the get call below would return None
        sslKeyFilePassphrase = thisSection.get('sslKeyFilePassphrase')
        if sslKeyFilePassphrase is None:
            sslKeyFilePassphrase = getpass.getpass(prompt="\ntest3Info owner "
                                              "credentials passphrase: ")

        credExists, errorTxt, fields = self.clnt.info(
                                 thisSection['username'],
                                 path.expandvars(thisSection['sslCertFile']),
                                 path.expandvars(thisSection['sslKeyFile']),
                                 sslKeyFilePassphrase=sslKeyFilePassphrase)
        print "test3Info... "
        print "credExists: %s" % credExists
        print "errorTxt: " + errorTxt
        print "fields: %s" % fields

    def test04ChangePassphrase(self):        
        # change pass-phrase protecting a given credential
        thisSection = self.cfg['test04ChangePassphrase']
        
        passphrase = thisSection.get('passphrase')
        if passphrase is None:
            passphrase = getpass.getpass(prompt="test4ChangePassphrase - "
                                                "passphrase: ")
        
        newPassphrase = thisSection.get('newPassphrase')
        if newPassphrase is None:
            newPassphrase = getpass.getpass(prompt="test4ChangePassphrase "
                                                   "- new passphrase: ")

            confirmNewPassphrase = getpass.getpass(prompt=\
                                                   "test4ChangePassphrase "
                                                   "- confirm new "
                                                   "passphrase: ")

            if newPassphrase != confirmNewPassphrase:
                self.fail("New and confirmed new password don't match")
                
        sslKeyFilePassphrase = thisSection.get('sslKeyFilePassphrase') or passphrase

        self.clnt.changePassphrase(thisSection['username'],
                               passphrase,
                               newPassphrase, 
                               path.expandvars(thisSection['sslCertFile']),
                               path.expandvars(thisSection['sslKeyFile']),
                               sslKeyFilePassphrase=sslKeyFilePassphrase)
        print("Changed pass-phrase")

    def test05Destroy(self):
        # destroy credentials for a given user
        thisSection = self.cfg['test05Destroy']
        
        sslKeyFilePassphrase = thisSection.get('sslKeyFilePassphrase')
        if sslKeyFilePassphrase is None:
            sslKeyFilePassphrase = getpass.getpass(prompt="\ntest5Destroy "
                                              "credential owner passphrase: ")

        self.clnt.destroy(thisSection['username'], 
                      sslCertFile=path.expandvars(thisSection['sslCertFile']),
                      sslKeyFile=path.expandvars(thisSection['sslKeyFile']),
                      sslKeyFilePassphrase=sslKeyFilePassphrase)
        print("Destroy creds for user %s" % thisSection['username'])
        
    def test06GetTrustRoots(self):
        # Test get trust roots command
        trustRoots = self.clnt.getTrustRoots()
        self.assert_(trustRoots)
        self.assert_(isinstance(trustRoots, dict))
        self.assert_(len(trustRoots) > 0)
        for fileName, fileContents in trustRoots.items():
            if fileName.endswith('.0'):
                # test parsing certificate
                cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                               fileContents)
                self.assert_(cert)
                self.assert_(isinstance(cert, crypto.X509))
                subj = cert.get_subject()
                self.assert_(subj)
                print("Trust root certificate retrieved with DN=%s" % subj)
        
        
from myproxy.utils.openssl import OpenSSLConfigError

class MyProxyClientInterfaceTestCase(_MyProxyClientTestCase):
    '''Test interface for correct getting/setting of attributes'''
    HOSTCERT_FILENAME = 'localhost.crt'
    HOSTCERT_FILEPATH = mkPath(HOSTCERT_FILENAME)
    HOSTCERT_DN = '/C=UK/ST=Oxfordshire/O=BADC/OU=Security/CN=localhost'
    
    def test01EnvironmentVarsSet(self):

        try:
            environBackup = os.environ.copy()
            
            os.environ['MYPROXY_SERVER'] = 'localhost.domain'
            os.environ['MYPROXY_SERVER_DN'] = '/O=NDG/OU=Raphael/CN=raphael'
            os.environ['MYPROXY_SERVER_PORT'] = '20000'
            client = MyProxyClient(openSSLConfFilePath=mkPath('openssl.conf'),
                                   proxyCertMaxLifetime=60000,
                                   proxyCertLifetime=30000,            
                                   caCertFilePath=mkPath('ndg-test-ca.crt'))
            
            self.assert_(client.port == 20000)
            self.assert_(client.hostname == 'localhost.domain')
            self.assert_(client.serverDN == '/O=NDG/OU=Raphael/CN=raphael')
            self.assert_(client.proxyCertMaxLifetime == 60000)
            self.assert_(client.proxyCertLifetime == 30000)
            self.assert_(client.openSSLConfFilePath == mkPath('openssl.conf'))
            self.assert_(client.caCertFilePath == mkPath('ndg-test-ca.crt'))
        finally:
            os.environ = environBackup       

    def test02SetProperties(self):
        
        client = MyProxyClient()
        try:
            client.port = None
            self.fail("Expecting AttributeError raised from port set to "
                      "invalid type")
        except TypeError:
            pass

        client.port = 8000
        client.hostname = '127.0.0.1'
        client.serverDN = '/O=NDG/OU=BADC/CN=raphael'
        client.proxyCertMaxLifetime = 80000
        client.proxyCertLifetime = 70000
        
        try:
            client.openSSLConfFilePath = mkPath('ssl.cnf')
            self.fail("Expecting OpenSSLConfigError raised for invalid file "
                      "'ssl.cnf'")
        except OpenSSLConfigError:
            pass
        
        client.caCertFilePath = mkPath('ca.pem') 
        client.caCertDir = mkPath('/etc/grid-security/certificates') 
        
        self.assert_(client.port == 8000)
        self.assert_(client.hostname == '127.0.0.1')
        self.assert_(client.serverDN == '/O=NDG/OU=BADC/CN=raphael')
        self.assert_(client.proxyCertMaxLifetime == 80000)
        self.assert_(client.proxyCertLifetime == 70000)
        self.assert_(client.openSSLConfFilePath == mkPath('ssl.cnf'))
        self.assert_(client.caCertFilePath == mkPath('ca.pem')) 
        self.assert_(
                client.caCertDir == mkPath('/etc/grid-security/certificates')) 
 
    def test03SSLVerification(self):
        # SSL verification callback
        
        # Ensure no relevant environment variables are set which might affect
        # the result
        try:
            serverDN = os.environ.get(
                                    MyProxyClient.MYPROXY_SERVER_DN_ENVVARNAME)
            if serverDN is not None:
                del os.environ[MyProxyClient.MYPROXY_SERVER_DN_ENVVARNAME]
        
            client = MyProxyClient()
            
            connection = None
            errorStatus = 1
            successStatus = 0
            errorDepth = 0
            peerCertStr = open(self.__class__.HOSTCERT_FILEPATH).read()
            peerCert = crypto.load_certificate(crypto.FILETYPE_PEM, peerCertStr)
            
            args = (connection, peerCert, errorStatus, errorDepth, 
                    successStatus)
            
            # This would normally called implicitly during the SSL handshake
            status = client.serverSSLCertVerify(*args)
            self.assert_(status == errorStatus)
            
            # Won't match because the default 'host/' CN prefix is set
            client.hostname = 'localhost'
            status = client.serverSSLCertVerify(*args)
            self.assert_(status == errorStatus)
            
            # Should now match
            client.serverCNPrefix = ''
            status = client.serverSSLCertVerify(*args)
            self.assert_(status == successStatus)
            
            # Match based on full DN instead - this takes precedence over
            # hostname match
            client.serverDN = self.__class__.HOSTCERT_DN
            status = client.serverSSLCertVerify(*args)
            self.assert_(status == successStatus)
            
        finally:
            if serverDN:
                os.environ[MyProxyClient.MYPROXY_SERVER_DN_ENVVARNAME
                           ] = serverDN
                                        
if __name__ == "__main__":
    unittest.main()
