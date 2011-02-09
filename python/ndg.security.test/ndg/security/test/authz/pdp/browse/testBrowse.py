#!/usr/bin/env python
"""Test harness for NDG Browse PDP and PEP - makes access control decisions
for MOLES and CSML documents

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "02/07/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import unittest
import os, sys, getpass, re
from ConfigParser import SafeConfigParser
import traceback
import logging
logging.basicConfig()
from ndg.security.common.authz.pdp.browse import BrowsePDP, \
    AttributeCertificateRequestError

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_PDP_UNITTEST_DIR'], file)


class BrowsePDPTestCase(unittest.TestCase):
    """Unit test case for ndg.security.common.authz.pdp.BrowsePDP class."""
      
    def setUp(self):
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_PDP_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_PDP_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))
        

        cfgFilePath = jnPath(os.environ['NDGSEC_PDP_UNITTEST_DIR'],
                             "browse.cfg")
        self.pdp = BrowsePDP(cfg=cfgFilePath)
        
                                  
    def test1Config(self):
        """test1Config - check client SOAP call is made correctly to 
        Session Manager - AttributeCertificateRequestError is expected
        because calling a non-existent Session Manager service"""
        
        print "\n\t" + self.test1Config.__doc__
        resrcHandle = dict(uri=xpdVars('file:///$NDGSEC_PDP_UNITTEST_DIR'),
                           doc='MOLES doc')
        userHandle = dict(h='https://localhost/sessionmanagerblah',
                           sid='abcdef012345',
                           u='testuser')

        #self.pdp(resrcHandle, userHandle, None)
        self.pdp.smURI = userHandle['h']
        try:
            self.pdp._pullUserSessionAttCert(self.pdp.aaURI, 'roleName')
        except AttributeCertificateRequestError:
            pass


#_____________________________________________________________________________       
class BrowsePDPTestSuite(unittest.TestSuite):
    
    def __init__(self):
        print "BrowsePDPTestSuite ..."
        testCaseMap = map(BrowsePDPTestCase,
                          (
                            "test1AccessPermitted",
                          ))
        unittest.TestSuite.__init__(self, testCaseMap)
            
                                                    
if __name__ == "__main__":
    unittest.main()        
