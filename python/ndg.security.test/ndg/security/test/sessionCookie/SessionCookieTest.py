#!/usr/bin/env python

"""Test harness for NDG Session Cookie

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "28/11/06"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

import unittest
import os, sys, getpass, base64
 
from ndg.security.common.sessionCookie import SessionCookie
from datetime import datetime, timedelta
from ConfigParser import SafeConfigParser, NoOptionError

xpdVars = os.path.expandvars
jnPath = os.path.join
mkPath=lambda file:jnPath(os.environ['NDGSEC_SESSIONCOOKIE_UNITTEST_DIR'],file)


class SessionCookieTestCase(unittest.TestCase):
    raise NotImplementedError(\
    "SessionCookie class not used in current implementation of NDG Security")
    priKeyPwd = None
        
    def setUp(self):
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_SESSIONCOOKIE_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_SESSIONCOOKIE_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))

        self.cookie = SessionCookie()
        
        configParser = SafeConfigParser()
        configFilePath=jnPath(os.environ['NDGSEC_SESSIONCOOKIE_UNITTEST_DIR'],
                              'sessionCookieTest.cfg')
        configParser.read(configFilePath)
        
        self.cookie.x509CertFilePath = xpdVars(configParser.get('setUp', 
                                                        'x509CertFilePath'))
        if self.__class__.priKeyPwd is None:
            try:
                self.__class__.priKeyPwd = configParser.get('setUp', 
                                                            'priKeyPwd')
            except NoOptionError:
                try:
                    self.__class__.priKeyPwd = getpass.getpass(\
                                prompt="\nsetUp - private key password: ")
                except KeyboardInterrupt:
                    raise SystemExit
        
        self.priKeyFilePath=xpdVars(configParser.get('setUp','priKeyFilePath'))
        
        self.cookie.x509CertFilePath = xpdVars(configParser.get('setUp', 
                                                        'x509CertFilePath'))
      
        self.cookie.create('O=NDG/OU=BADC/CN=test',
                           base64.encodestring(os.urandom(32)).strip(),
                           'http://localhost:5000/SessionManager')
        
            
    def test1GetSessID(self):
        """test1GetSessID: check session ID attribute"""       
        print "Test get session ID: \n%s" % self.cookie.sessID
      
    def test2GetUserDN(self):
        """test2GetUserDN: check user DN attribute"""       
        print "Test get user DN: \n%s" % self.cookie.userDN
      
    def test3GetSessMgrURI(self):
        """test3GetSessMgrURI: check Session Manager URI attribute"""       
        print "Test get Session Manager URI: \n%s" % self.cookie.sessMgrURI

    def test4AsString(self):
        """test4AsString: check conversion to string"""
        print "Print as string: %s" % self.cookie
        
    def test5Parse(self):
        """test5Parse: check parsing from string"""       
        print "Test parse from string: \n"
        newCookie = SessionCookie()
        newCookie.priKeyPwd = self.__class__.priKeyPwd
        newCookie.priKeyFilePath = self.priKeyFilePath
        
        cookie = newCookie.parse(str(self.cookie))
        print "Session ID: \n%s" % newCookie.sessID
        print "User DN: \n%s" % newCookie.userDN
        print "Session Manager URI: \n%s" % newCookie.sessMgrURI
                  
            
#_____________________________________________________________________________       
class SessionCookieTestSuite(unittest.TestSuite):
    
    def __init__(self):
        map = map(SessionCookieTestCase,
                  (
                    "test1GetSessID",
                    "test2GetUserDN",
                    "test3GetSessMgrURI",
                    "test4AsString",
                    "test5Parse",
                  ))
        unittest.TestSuite.__init__(self, map)
            
                                                    
if __name__ == "__main__":
    unittest.main()        
