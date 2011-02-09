#!/usr/bin/env python
"""NDG MyProxy client unit tests

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "02/07/07"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

import unittest
import os
import sys
import getpass
import traceback

from ConfigParser import SafeConfigParser
from ndg.security.server.MyProxy import MyProxyClient

xpdVars = os.path.expandvars
jnPath = os.path.join
mkPath = lambda file: jnPath(os.environ['NDGSEC_MYPROXY_UNITTEST_DIR'], file)

class MyProxyClientTestCase(unittest.TestCase):
    
    def setUp(self):
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_MYPROXY_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_MYPROXY_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))
                
        configParser = SafeConfigParser()
        configFilePath = jnPath(os.environ['NDGSEC_MYPROXY_UNITTEST_DIR'],
                                "myProxyClientTest.cfg")
        configParser.read(configFilePath)
        
        self.cfg = {}
        for section in configParser.sections():
            self.cfg[section] = dict(configParser.items(section))
            
        self.clnt = MyProxyClient(\
                    propFilePath=xpdVars(self.cfg['setUp']['propfilepath']))
        

    def test1Store(self):
        '''test1Store: upload X509 cert and private key to repository'''
            
        passphrase = self.cfg['test1Store'].get('passphrase')
        if passphrase is None:
            passphrase = getpass.getpass(\
                                 prompt="\ntest1Store cred. pass-phrase: ")
            
        ownerPassphrase = self.cfg['test1Store'].get('ownerpassphrase')
        if ownerPassphrase is None:
            ownerPassphrase = getpass.getpass(\
                              prompt="\ntest1Store cred. owner pass-phrase: ")

        certFile = xpdVars(self.cfg['test1Store']['certfile'])
        keyFile = xpdVars(self.cfg['test1Store']['keyfile'])
        ownerCertFile = xpdVars(self.cfg['test1Store']['ownercertfile'])
        ownerKeyFile = xpdVars(self.cfg['test1Store']['ownerkeyfile'])
            
        try:
            self.clnt.store(self.cfg['test1Store']['username'],
                            passphrase,
                            certFile,
                            keyFile,
                            ownerCertFile=ownerCertFile,
                            ownerKeyFile=ownerKeyFile,
                            ownerPassphrase=ownerPassphrase,
                            force=False)
            print "Store creds for user %s" % \
                                            self.cfg['test1Store']['username']
        except:
            self.fail(traceback.print_exc())
    
    
    def test2GetDelegation(self):
        '''test2GetDelegation: retrieve proxy cert./private key'''
        passphrase = self.cfg['test2GetDelegation'].get('passphrase')
        if passphrase is None:
            passphrase = getpass.getpass(\
                                 prompt="\ntest2GetDelegation pass-phrase: ")
         
        try:
            proxyCertFile = \
                xpdVars(self.cfg['test2GetDelegation']['proxycertfileout'])
            proxyKeyFile = \
                xpdVars(self.cfg['test2GetDelegation']['proxykeyfileout'])

            creds = self.clnt.getDelegation(\
                                  self.cfg['test2GetDelegation']['username'], 
                                  passphrase)
            print "proxy credentials:" 
            print ''.join(creds)
            open(proxyCertFile, 'w').write(creds[0]+''.join(creds[2:]))            
            open(proxyKeyFile, 'w').write(creds[1])
        except:
            self.fail(traceback.print_exc())


    def test3Info(self):
        '''test3Info: Retrieve information about a given credential'''
        
        # ownerpassphrase can be omitted from the congif file in which case
        # the get call below would return None
        ownerPassphrase = self.cfg['test3Info'].get('ownerpassphrase')
        if ownerPassphrase is None:
            ownerPassphrase = getpass.getpass(\
                              prompt="\ntest3Info owner creds pass-phrase: ")

        try:
            credExists, errorTxt, fields = self.clnt.info(
                             self.cfg['test3Info']['username'],
                             xpdVars(self.cfg['test3Info']['ownercertfile']),
                             xpdVars(self.cfg['test3Info']['ownerkeyfile']),
                             ownerPassphrase=ownerPassphrase)
            print "test3Info... "
            print "credExists: %s" % credExists
            print "errorTxt: " + errorTxt
            print "fields: %s" % fields
        except:
            self.fail(traceback.print_exc())


    def test4ChangePassphrase(self):        
        """test4ChangePassphrase: change pass-phrase protecting a given
        credential"""
        try:
            passphrase=self.cfg['test4ChangePassphrase'].get('passphrase')
            if passphrase is None:
                passphrase = getpass.getpass(\
                             prompt="test4ChangePassphrase - pass-phrase: ")
            
            newPassphrase = \
                        self.cfg['test4ChangePassphrase'].get('newpassphrase')
            if newPassphrase is None:
                newPassphrase = getpass.getpass(\
                        prompt="test4ChangePassphrase - new pass-phrase: ")
    
                confirmNewPassphrase = getpass.getpass(\
                prompt="test4ChangePassphrase - confirm new pass-phrase: ")
    
                if newPassphrase != confirmNewPassphrase:
                    self.fail("New and confirmed new password don't match")
                    
            ownerPassphrase = \
                self.cfg['test4ChangePassphrase'].get('ownerpassphrase') or \
                passphrase
    
            self.clnt.changePassphrase(
                self.cfg['test4ChangePassphrase']['username'],
                passphrase,
                newPassphrase, 
                xpdVars(self.cfg['test4ChangePassphrase']['ownercertfile']),
                xpdVars(self.cfg['test4ChangePassphrase']['ownerkeyfile']),
                ownerPassphrase=ownerPassphrase)
            print "Change pass-phrase"
        except:
            self.fail(traceback.print_exc())


    def test5Destroy(self):
        '''test5Destroy: destroy credentials for a given user'''

        ownerPassphrase = self.cfg['test5Destroy'].get('ownerpassphrase')
        if ownerPassphrase is None:
            ownerPassphrase = getpass.getpass(\
                          prompt="\ntest5Destroy cred. owner pass-phrase: ")

        try:
            self.clnt.destroy(self.cfg['test5Destroy']['username'], 
            ownerCertFile=xpdVars(self.cfg['test5Destroy']['ownercertfile']),
            ownerKeyFile=xpdVars(self.cfg['test5Destroy']['ownerkeyfile']),
            ownerPassphrase=ownerPassphrase)
            print "Destroy creds for user %s" % \
                                        self.cfg['test5Destroy']['username']
        except:
            self.fail(traceback.print_exc())
        
 
#_____________________________________________________________________________       
class MyProxyClientTestSuite(unittest.TestSuite):
    def __init__(self):
        map = map(MyProxyClientTestCase,
                  (
                    "test1Store",
                    "test2GetDelegation",
                    "test3Info",
                    "test4ChangePassphrase",
                    "test5Destroy",
                  ))
        unittest.TestSuite.__init__(self, map)
                                        
if __name__ == "__main__":
    unittest.main()
