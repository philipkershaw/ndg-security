#!/usr/bin/env python
"""NDG Security Session Manager test harness for client unit tests

NERC Data Grid Project

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
__author__ = "P J Kershaw"
__date__ = "29/09/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import os
from os.path import dirname, abspath, join

def infoApp(environ, start_response):
    start_response('200 OK', [('Content-type', 'text/plain')])
    return "NDG Security Session Manager for Client Unit Tests"

def app_factory(global_config, **local_conf):
    return infoApp

from ndg.security.test import BaseTestCase

# Initialize environment for unit tests
if BaseTestCase.configDirEnvVarName not in os.environ:
    os.environ[BaseTestCase.configDirEnvVarName] = \
                                            dirname(abspath(dirname(__file__)))

# To start the Site A Session Manager run 
# $ paster serve site-a.ini or run this file as a script
# $ ./siteAServerApp.py [port #]
if __name__ == '__main__':
    import sys
    import logging
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 5500
        
    cfgFilePath = os.path.join(dirname(abspath(__file__)),
                               'session-manager.ini')
        
    from paste.httpserver import serve
    from paste.deploy import loadapp

    app = loadapp('config:%s' % cfgFilePath)
    serve(app, host='0.0.0.0', port=port)