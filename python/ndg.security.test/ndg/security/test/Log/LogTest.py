#!/usr/bin/env python
"""NDG Logging class test harness

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "12/05/06"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

import unittest
import os
import logging
#logging.basicConfig(level=logging.DEBUG,
#                    format='%(asctime)s %(levelname)-8s %(message)s',
#                    datefmt='%a, %d %b %Y %H:%M:%S',
#                    filename='./ndg.log',
#                    filemode='w')
from logging.config import fileConfig
fileConfig('log.cfg')
log = logging.getLogger(__name__)

class LogTestCase(unittest.TestCase):

    def setUp(self):
        pass
    
    def __output(self):
        print log
        log.info('Jackdaws love my big sphinx of quartz.')
    
        log.debug('Quick zephyrs blow, vexing daft Jim.')
        log.info('How quickly daft jumping zebras vex.')
        log.warning('Jail zesty vixen who grabbed pay from quack.')
        log.error('The five boxing wizards jump quickly.')


    def test1(self):
        self.__output()
          
            
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