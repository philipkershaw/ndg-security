#!/usr/bin/env python
"""NDG Security Attribute Authority test harness for unit test site 'A'

NERC Data Grid Project

"""
__author__ = "P J Kershaw"
__date__ = "24/09/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import os
from os.path import dirname, abspath, join

def infoApp(environ, start_response):
    response = "NDG Security Attribute Authority Unit Tests: Site A Server"
    start_response('200 OK', [('Content-type', 'text/plain'),
                              ('Content-length', str(len(response)))])
    return [response]

def app_factory(global_config, **local_conf):
    return infoApp

from ndg.security.test.unit import BaseTestCase

# Initialize environment for unit tests
if BaseTestCase.configDirEnvVarName not in os.environ:
    os.environ[BaseTestCase.configDirEnvVarName] = \
                                dirname(dirname(abspath(dirname(__file__))))

# To start the Site A Attribute Authority run 
# $ paster serve site-a.ini or run this file as a script
# $ ./siteAServerApp.py [port #]
if __name__ == '__main__':
    import sys
    import logging
#    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 5000
        
    cfgFilePath = join(dirname(abspath(__file__)), 'site-a.ini')
        
    from paste.httpserver import serve
    from paste.deploy import loadapp
    from paste.script.util.logging_config import fileConfig
    
    fileConfig(cfgFilePath)
    app = loadapp('config:%s' % cfgFilePath)
    serve(app, host='0.0.0.0', port=port)