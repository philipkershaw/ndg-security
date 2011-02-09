#!/usr/bin/env python
"""NDG Logging class test harness

NERC Data Grid Project

P J Kershaw 12/05/06

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
import unittest

class LogTestCase(unittest.TestCase):

    def setup(self):
        self.log = Log(logFilePath="./ndg.log", console=True)
        
    def test(self):
        
        # Now, we can log to the root logger, or any other logger. First the root...
        try:
            self.log.info('Jackdaws love my big sphinx of quartz.')
        
            self.log.debug('Quick zephyrs blow, vexing daft Jim.')
            self.log.info('How quickly daft jumping zebras vex.')
            self.log.warning('Jail zesty vixen who grabbed pay from quack.')
            self.log.error('The five boxing wizards jump quickly.')
            
        except Exception, e:
            self.fail(str(e))
            
            
#_____________________________________________________________________________       
class LogTestSuite(unittest.TestSuite):
    
    def __init__(self):
        map = map(LogTestCase,
                  (
                    "test",
                  ))
        unittest.TestSuite.__init__(self, map)
            
                                                    
if __name__ == "__main__":
    unittest.main()