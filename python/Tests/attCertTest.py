#!/bin/env python

import unittest
from NDG.AttCert import *


class attCertTestCase(unittest.TestCase):
    
    def setUp(self):
        pass
    
    def tearDown(self):
        pass

    def testAttCertNonZero(self):
        
        try:
            attCert = AttCert()
            if not attCert:
                self.fail("AttCert instance yields 0")
            
        except Exception, e:
            self.fail(str(e))
        

class attCertTestSuite(unittest.TestSuite):
    def __init__(self):
        map = map(attCertTestCase,
                  (
                    "testAttCertNonZero",
                  ))
        unittest.TestSuite.__init__(self, map)
                                        
if __name__ == "__main__":
    unittest.main()