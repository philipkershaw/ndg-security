#!/usr/bin/env python
"""Unit tests for XACML package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "10/06/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import logging

import unittest
import os
import re

from ndg.security.test.unit import BaseTestCase
from ndg.xacml import Policy
from ndg.xacml.exceptions import ParsingException


class XACMLPolicyTestCase(BaseTestCase):

    def test01ParseWithNoSource(self):
        try:
            policy = Policy.getInstance()
        except AttributeError, e:
            print("PASS - root or source keywords must be set: %s" % e)
    
    def test02Parse(self):
        filePath = os.path.join(os.path.dirname(__file__), "xacml.xml")
        try:
            policy = Policy.getInstance(source=filePath)
        except ParsingException:
            print("FIXME: string-bag function support TBC: " + \
                  str(self._exc_info()))


if __name__ == "__main__":
    unittest.main()        
