#!/usr/bin/env python
"""WS-Security Digital Signature unit tests

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "13/12/06"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)

import unittest
import os
import sys
import getpass
import traceback

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_WSSECLNT_UNITTEST_DIR'], file)
from ConfigParser import SafeConfigParser

from EchoService_services import EchoServiceLocator

from ndg.security.test import BaseTestCase
from ndg.security.common.wssecurity.dom import SignatureHandler

class EchoClientTestCase(BaseTestCase):
    
    def setUp(self):
        super(EchoClientTestCase, self).setUp()
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_WSSECLNT_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_WSSECLNT_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))
        
        configFilePath = mkPath('echoClientTest.cfg')
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
        sigHandler = SignatureHandler(
                                 signingPriKeyFilePath=signingPriKeyFilePath,
                                 signingPriKeyPwd=signingPriKeyPwd,
                                 signingCertFilePath=signingCertFilePath,
                                 caCertFilePathList=caCertFilePathList,
                                 refC14nInclNS=[],
                                 signedInfoC14nInclNS=[])

        locator = EchoServiceLocator()
        self.clnt = locator.getEcho(uri, 
                                    sig_handler=sigHandler,
                                    tracefile=sys.stderr)
        

    def test1Echo(self):
        '''test1Echo: test signed message and signed response from server'''
            
        try:
            resp = self.clnt.Echo("Hello from client")
            print "Message returned was: %s" % resp
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
