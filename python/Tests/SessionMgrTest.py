#!/bin/env python

import unittest
from ndg.security.server.Session import *


class SessionMgrTestCase(unittest.TestCase):
    
    def setUp(self):
        """Nb. Credential Repository interface dynamic load is implict"""
        self.propFilePath = './sessionMgrProperties.xml'
        self.sessMgr = SessionMgr(propFilePath=self.propFilePath)
    
    def tearDown(self):
        pass

    def testExplicitReadPropAndLoadCredReposInt(self):
        '''Test for loading Credential Repository SEPARATE to __init__'''
        sessMgr = SessionMgr()
        sessMgr.readProperties(self.propFilePath)
        sessMgr.loadCredReposInterface()
        
    def testCredReposAudit(self):
        import pdb;pdb.set_trace()
        self.sessMgr.auditCredRepos()
                               
class SessionMgrTestSuite(unittest.TestSuite):
    def __init__(self):
        map = map(SessionMgrTestCase,
                  (testExplicitReadPropAndLoadCredReposInt,
                   testCredReposAudit)
                 )
        unittest.TestSuite.__init__(self, map)
                                        
if __name__ == "__main__":
    unittest.main()