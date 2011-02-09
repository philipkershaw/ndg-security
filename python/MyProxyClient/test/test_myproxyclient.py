#!/usr/bin/env python
"""MyProxy Client unit tests

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "02/07/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = """LGPL"""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import unittest
import os
import sys
import getpass
import traceback

from myproxy.client import CaseSensitiveConfigParser, MyProxyClient

xpdVars = os.path.expandvars
jnPath = os.path.join
mkPath = lambda file: jnPath(os.environ['MYPROXYCLIENT_UNITTEST_DIR'], file)

class _MyProxyClientTestCase(unittest.TestCase):
    '''Base implements environment settings common to all test case classes'''
    if 'NDGSEC_INT_DEBUG' in os.environ:
        import pdb
        pdb.set_trace()
    
    if 'MYPROXYCLIENT_UNITTEST_DIR' not in os.environ:
        os.environ['MYPROXYCLIENT_UNITTEST_DIR'] = \
            os.path.abspath(os.path.dirname(__file__))


class MyProxyClientLiveTestCase(_MyProxyClientTestCase):
    '''Tests require a connection to a real MyProxy service running on a host
    '''
    
    def setUp(self):
        
        super(MyProxyClientLiveTestCase, self).setUp()
        
        configParser = CaseSensitiveConfigParser()
        configFilePath = jnPath(os.environ['MYPROXYCLIENT_UNITTEST_DIR'],
                                "myProxyClientTest.cfg")
        configParser.read(configFilePath)
        
        self.cfg = {}
        for section in configParser.sections():
            self.cfg[section] = dict(configParser.items(section))
            
        self.clnt = MyProxyClient(
                        cfgFilePath=xpdVars(self.cfg['setUp']['cfgFilePath']))
        

    def test1Store(self):
        '''test1Store: upload X509 cert and private key to repository'''
        thisSection = self.cfg['test1Store']
        
        passphrase = thisSection.get('passphrase')
        if passphrase is None:
            passphrase = getpass.getpass(prompt="\ntest1Store credential "
                                                "pass-phrase: ")
            
        ownerPassphrase = thisSection.get('ownerPassphrase')
        if ownerPassphrase is None:
            ownerPassphrase = getpass.getpass(prompt="\ntest1Store credential "
                                                     " owner pass-phrase: ")

        certFile = xpdVars(thisSection['signingCertFilePath'])
        keyFile = xpdVars(thisSection['signingPriKeyFilePath'])
        ownerCertFile = xpdVars(thisSection['ownerCertFile'])
        ownerKeyFile = xpdVars(thisSection['ownerKeyFile'])
            
        self.clnt.store(thisSection['username'],
                        passphrase,
                        certFile,
                        keyFile,
                        ownerCertFile=ownerCertFile,
                        ownerKeyFile=ownerKeyFile,
                        ownerPassphrase=ownerPassphrase,
                        force=False)
        print("Store creds for user %s" % thisSection['username'])
    
    
    def test2GetDelegation(self):
        '''test2GetDelegation: retrieve proxy cert./private key'''
        thisSection = self.cfg['test2GetDelegation']
        
        passphrase = thisSection.get('passphrase')
        if passphrase is None:
            passphrase = getpass.getpass(prompt="\ntest2GetDelegation "
                                                "passphrase: ")
         
        proxyCertFile = xpdVars(thisSection['proxyCertFileOut'])
        proxyKeyFile = xpdVars(thisSection['proxyKeyFileOut'])

        creds = self.clnt.getDelegation(thisSection['username'], 
                                        passphrase)
        print "proxy credentials:" 
        print ''.join(creds)
        open(proxyCertFile, 'w').write(creds[0]+''.join(creds[2:]))            
        open(proxyKeyFile, 'w').write(creds[1])


    def test3Info(self):
        '''test3Info: Retrieve information about a given credential'''
        thisSection = self.cfg['test3Info']
        
        # ownerPassphrase can be omitted from the congif file in which case
        # the get call below would return None
        ownerPassphrase = thisSection.get('ownerPassphrase')
        if ownerPassphrase is None:
            ownerPassphrase = getpass.getpass(prompt="\ntest3Info owner "
                                              "credentials passphrase: ")

        credExists, errorTxt, fields = self.clnt.info(
                                     thisSection['username'],
                                     xpdVars(thisSection['ownerCertFile']),
                                     xpdVars(thisSection['ownerKeyFile']),
                                     ownerPassphrase=ownerPassphrase)
        print "test3Info... "
        print "credExists: %s" % credExists
        print "errorTxt: " + errorTxt
        print "fields: %s" % fields


    def test4ChangePassphrase(self):        
        """test4ChangePassphrase: change pass-phrase protecting a given
        credential"""
        thisSection = self.cfg['test4ChangePassphrase']
        
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
                
        ownerPassphrase = thisSection.get('ownerPassphrase') or passphrase

        self.clnt.changePassphrase(thisSection['username'],
                                   passphrase,
                                   newPassphrase, 
                                   xpdVars(thisSection['ownerCertFile']),
                                   xpdVars(thisSection['ownerKeyFile']),
                                   ownerPassphrase=ownerPassphrase)
        print("Changed pass-phrase")


    def test5Destroy(self):
        '''test5Destroy: destroy credentials for a given user'''
        thisSection = self.cfg['test5Destroy']
        
        ownerPassphrase = thisSection.get('ownerPassphrase')
        if ownerPassphrase is None:
            ownerPassphrase = getpass.getpass(prompt="\ntest5Destroy "
                                              "credential owner passphrase: ")

        self.clnt.destroy(thisSection['username'], 
                          ownerCertFile=xpdVars(thisSection['ownerCertFile']),
                          ownerKeyFile=xpdVars(thisSection['ownerKeyFile']),
                          ownerPassphrase=ownerPassphrase)
        print("Destroy creds for user %s" % thisSection['username'])
        
        
from myproxy.utils.openssl import OpenSSLConfigError

class MyProxyClientInterfaceTestCase(_MyProxyClientTestCase):
    '''Test interface for correct getting/setting of attributes'''
    
    def test01EnvironmentVarsSet(self):

        try:
            environBackup = os.environ.copy()
            
            os.environ['MYPROXY_SERVER'] = 'localhost.domain'
            os.environ['MYPROXY_SERVER_DN'] = '/O=NDG/OU=Raphael/CN=raphael'
            os.environ['MYPROXY_SERVER_PORT'] = '20000'
            client = MyProxyClient(serverCNPrefix='',
                                   openSSLConfFilePath=mkPath('openssl.conf'),
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
        except AttributeError:
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
                                        
if __name__ == "__main__":
    unittest.main()
