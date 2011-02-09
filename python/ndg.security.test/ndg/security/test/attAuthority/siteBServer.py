#!/usr/bin/env python
"""Site 'B' Attribute Authority server start-up script for unit test - replaces
former bash script

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "07/01/08"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id:$'
import sys, os, string
if string.find(os.path.abspath(sys.argv[0]), os.sep+'Twisted') != -1:
    sys.path.insert(0, os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]), os.pardir, os.pardir)))
if hasattr(os, "getuid") and os.getuid() != 0:
    sys.path.insert(0, os.path.abspath(os.getcwd()))
### end of preamble

from twisted.python.runtime import platformType
if platformType == "win32":
    from twisted.scripts._twistw import run
else:
    from twisted.scripts.twistd import run

from tempfile import mkstemp

if 'NDGSEC_AACLNT_UNITTEST_DIR' not in os.environ:
    os.environ['NDGSEC_AACLNT_UNITTEST_DIR'] = \
                        os.path.abspath(os.path.dirname(__file__))
    
if 'NDGSEC_AA_PROPFILEPATH' not in os.environ:
    os.environ['NDGSEC_AA_PROPFILEPATH'] = \
                        os.path.join(os.environ['NDGSEC_AACLNT_UNITTEST_DIR'],
                                     "siteBAttAuthorityProperties.xml")
    
if 'NDGSEC_DIR' in os.environ:
    tacFilePath=os.path.join(os.environ['NDGSEC_DIR'],
                             "conf",
                             "attAuthority.tac")
else:
    import pkg_resources
    eggConfigDir=pkg_resources.resource_filename('ndg.security.server','conf')
    os.environ['NDGSEC_DIR'] = os.path.dirname(eggConfigDir)
    tacFilePath = os.path.join(eggConfigDir, "attAuthority.tac")

sys.argv += ["--pidfile=twistd-%d.pid" % os.getpid(), "-noy", tacFilePath]
run()