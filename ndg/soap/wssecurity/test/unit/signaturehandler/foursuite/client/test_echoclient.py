#!/usr/bin/env python
"""WS-Security Digital Signature unit tests

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "22/01/2010"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import logging
logging.basicConfig(level=logging.DEBUG)

import os
import sys

from os.path import join, dirname, abspath
mkPath = lambda file: join(os.environ['NDGSOAP_WSSECLNT_UNITTEST_DIR'], file)

from ConfigParser import SafeConfigParser

from EchoService_services import EchoServiceLocator

from ndg.soap.utils.zsi import DomletteReader, DomletteElementProxy
from ndg.soap.wssecurity.test.unit import BaseTestCase
from ndg.soap.wssecurity import TimestampError
from ndg.soap.wssecurity.signaturehandler import (NoSignatureFound, 
                                                  SignatureHandlerFactory)


class EchoClientTestCase(BaseTestCase):
    """Test 4Suite-XML based WS-Security Signature Handler"""
    
    def setUp(self):
        super(EchoClientTestCase, self).setUp()
        
        if 'NDGSOAP_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSOAP_WSSECLNT_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSOAP_WSSECLNT_UNITTEST_DIR'] = \
                abspath(dirname(__file__))

        configFilePath = mkPath('echoClientTest.cfg')
        self.cfg = SafeConfigParser()
        self.cfg.read(configFilePath)
        uri = self.cfg.get('setUp', 'uri')
        
        # Signature handler object is passed to binding
        sigHandler = SignatureHandlerFactory.fromConfigFile(configFilePath, 
                                                            sectionName='setUp')

        locator = EchoServiceLocator()
        self.clnt = locator.getEcho(uri,
                                    readerclass=DomletteReader,
                                    writerclass=DomletteElementProxy, 
                                    sig_handler=sigHandler,
                                    tracefile=sys.stderr)
        
    def test01Echo(self):
            
        resp = self.clnt.Echo("Hello from client")
        print("Message returned was: %s" % resp)

    def test02ServerRaiseMissingTimestampError(self):
        # Get server to catch that no timestamp was provided
        
        self.clnt.binding.sig_handler.addTimestamp = False
        try:
            resp = self.clnt.Echo("Hello again from client")
            
        except NoSignatureFound:
            print("PASSED - server rejected client message with no timestamp")
        else:
            self.fail("Expecting error from server because client didn't set "
                      "a timestamp element")

    def test03ClientRaiseTimestampError(self):
        # Get client to catch a mismatch in the created time for the server
        # response by adding a clock skew to the client
        
        self.clnt.binding.sig_handler.timestampClockSkew = -300.0
        try:
            resp = self.clnt.Echo("Hello again from client")
            
        except TimestampError:
            print "PASSED - client rejected server message created timestamp"
        else:
            self.fail("Expecting error from client because client set a "
                      "a timestamp clock skew")

if __name__ == "__main__":
    unittest.main()
