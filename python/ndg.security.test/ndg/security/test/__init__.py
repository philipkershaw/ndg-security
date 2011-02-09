"""NDG Security Unit test package

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "24/12/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import unittest
import logging
logging.basicConfig()

import os
from os.path import expandvars as xpdVars
from os.path import join as jnPath


class BaseTestCase(unittest.TestCase):
    '''Convenience base class from which other unit tests can extend.  Its
    sets the generic data directory path'''
    configDirEnvVarName = 'NDGSEC_UNITTEST_CONFIG_DIR'
    
    def setUp(self):
        if BaseTestCase.configDirEnvVarName not in os.environ:
            os.environ[BaseTestCase.configDirEnvVarName] = \
                os.path.join(os.path.abspath(os.path.dirname(__file__)),
                             'config')

mkDataDirPath = lambda file:jnPath(os.environ[BaseTestCase.configDirEnvVarName],
                                   file)

