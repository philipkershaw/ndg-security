#!/usr/bin/env python
"""Test harness for NDG Session Manager - makes requests for 
authentication and authorisation.  An Attribute Authority and Simple CA
services must be running for the reqAuthorisation and addUser tests

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/11/07"
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

from ndg.security.common.authz.pdp.proftp import ProftpPDP

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_PDP_UNITTEST_DIR'], file)


class ProftpPDPTestCase(unittest.TestCase):
    """Unit test case for ndg.security.common.authz.pdp.ProftpPDP class."""
    
    
    def setUp(self):
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_PDP_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_PDP_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))
        

        cfgFilePath = jnPath(os.environ['NDGSEC_PDP_UNITTEST_DIR'],
                             "proftp-pdp.cfg")
        self.pdp = ProftpPDP(cfgFilePath=cfgFilePath)
        
                                  
#    def test1AccessPermitted(self):
#        """test1AccessPermitted"""
#        
#        print "\n\t" + self.test1AccessPermitted.__doc__
#        resrcHandle = {
#            'dir': os.environ['NDGSEC_PDP_UNITTEST_DIR']
#        }
#        
#        userHandle = {
#            'h': None,
#            'sid': None
#        }
#
#        self.pdp(resrcHandle, userHandle, None)
                                                    
if __name__ == "__main__":
    unittest.main()        
