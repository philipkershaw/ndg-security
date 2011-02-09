#!/usr/bin/env python
"""Unit tests for SSLClientAuthNMiddleware class

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "12/12/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import logging
logging.basicConfig(level=logging.DEBUG)

import unittest
import os

from urlparse import urlparse
from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_SSLCLNTAUTHN_UNITTEST_DIR'],
                             file)

from ndg.security.test.unit import BaseTestCase
from ndg.security.common.utils.configfileparsers import \
                                                    CaseSensitiveConfigParser
from ndg.security.common.utils.m2crypto import HTTPSConnection


class SSLClientAuthNMiddlewareTestCase(BaseTestCase):
    """Unit test case for 
    ndg.security.server.wsgi.sslclientauthn.SSLClientAuthNMiddleware class.
    """
    
    def setUp(self):
        super(SSLClientAuthNMiddlewareTestCase, self).setUp()
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_SSLCLNTAUTHN_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_SSLCLNTAUTHN_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))
        
        self.cfg = CaseSensitiveConfigParser()
        configFilePath = mkPath("sslClientAuthN.cfg")
        self.cfg.read(configFilePath)
        url = urlparse(self.cfg.get('DEFAULT', 'url'))
        self.hostname = url.netloc
        assert url.scheme=='https', "Expecting https transport for target URL"
            
    def test01CheckAccessSecuredURLSucceeds(self):
        thisSection = 'test01CheckAccessSecuredURLSucceeds'
        
        clntCertFilePath = xpdVars(os.path.join('$NDGSEC_TEST_CONFIG_DIR',
                                                'pki', 
                                                'test.crt'))
        clntPriKeyFilePath=xpdVars(os.path.join('$NDGSEC_TEST_CONFIG_DIR',
                                                'pki', 
                                                'test.key'))
        con = HTTPSConnection(self.hostname, 
                              clntCertFilePath=clntCertFilePath,
                              clntPriKeyFilePath=clntPriKeyFilePath)
        con.putrequest('GET', self.cfg.get(thisSection, 'path'))
        con.endheaders()
        resp = con.getresponse()
        print("\nResponse from server: \n%s\n%s" % ('_'*80, resp.read()))
        self.assert_(resp.status == 200)
            
    def test02CheckAccessSecuredURLFails(self):
        thisSection = 'test02CheckAccessSecuredURLFails'
        
        # Omit client cert and private key and check that the server rejects
        # the request
        con = HTTPSConnection(self.hostname)
        con.putrequest('GET', self.cfg.get(thisSection, 'path'))
        con.endheaders()
        resp = con.getresponse()
        print("\nResponse from server: \n%s\n%s" % ('_'*80, resp.read()))
        self.assert_(resp.status == 401)

    def test03CheckAccessNonSecuredURLSucceeds(self):
        thisSection = 'test03CheckAccessNonSecuredURLSucceeds'
        con = HTTPSConnection(self.hostname)
        con.putrequest('GET', self.cfg.get(thisSection, 'path'))
        con.endheaders()
        resp = con.getresponse()
        print("\nResponse from server: \n%s\n%s" % ('_'*80, resp.read()))
        self.assert_(resp.status == 200)
        
                                                         
if __name__ == "__main__":
    unittest.main()        
