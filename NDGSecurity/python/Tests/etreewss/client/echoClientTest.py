#!/usr/bin/env python
#
# Exampe echo client, to show extended code generation in ZSI
#
# Import the client proxy object
from EchoService_services import EchoServiceLocator

import unittest
import os
import sys
import getpass
import traceback

from ConfigParser import SafeConfigParser
from ndg.security.common.wssecurity.signaturehandler.etree import SignatureHandler, \
                                                NoSignatureFound

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_WSSECLNT_UNITTEST_DIR'], file)

from ndg.security.common.zsi.elementtreeproxy import ElementTreeProxy

import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

class EchoClientTestCase(unittest.TestCase):
    
    def setUp(self):
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_WSSECLNT_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_WSSECLNT_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))
        
        configFilePath = jnPath(os.environ['NDGSEC_WSSECLNT_UNITTEST_DIR'],
                                "echoClientTest.cfg")
        self.cfg = SafeConfigParser()
        self.cfg.read(configFilePath)
        uri = self.cfg.get('setUp', 'uri')
        signingPriKeyFilePath = \
                        xpdVars(self.cfg.get('setUp', 'signingPriKeyFilePath'))
        signingPriKeyPwd = self.cfg.get('setUp', 'signingPriKeyPwd')
        signingCertFilePath = \
                        xpdVars(self.cfg.get('setUp', 'signingCertFilePath'))
        caCertFilePathList = [xpdVars(file) for file in \
                              self.cfg.get('setUp', 
                                          'caCertFilePathList').split()]
        
        # Signature handler object is passed to binding
        # TODO: swap 'unsupressedPrefixes' to 'inclusive_namespaces' in
        # wssecurity.WSSecurityConfig
        sigHandler = SignatureHandler(
                                 signingPriKeyFilePath=signingPriKeyFilePath,
                                 signingPriKeyPwd=signingPriKeyPwd,
                                 signingCertFilePath=signingCertFilePath,
                                 caCertFilePathList=caCertFilePathList)

        locator = EchoServiceLocator()
        self.clnt = locator.getEcho(uri, 
                                    readerclass=ElementTreeProxy,
                                    writerclass=ElementTreeProxy,
                                    sig_handler=sigHandler,
                                    tracefile=sys.stderr)
        

    def test1Echo(self):
        '''test1Echo: test signed message and signed response from server'''
            
        try:  
            resp = self.clnt.Echo("Hello from client")
            log.info("Message returned was: %s", resp)
        except NoSignatureFound:
            log.info("No signature in response")
        except:
            self.fail(traceback.print_exc())
     
#_____________________________________________________________________________       
class EchoClientTestSuite(unittest.TestSuite):
    def __init__(self):
        map = map(EchoClientTestCase,
                  (
                    "test1Echo",
                  ))
        unittest.TestSuite.__init__(self, map)
                                        
if __name__ == "__main__":
    unittest.main()
