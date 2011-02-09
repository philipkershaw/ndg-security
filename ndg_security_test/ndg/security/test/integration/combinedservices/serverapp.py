#!/usr/bin/env python
"""NDG Security test harness for combined Session Manager and Attribute
Authority services running under a single Paste instance.

NERC Data Grid Project

"""
__author__ = "P J Kershaw"
__date__ = "20/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
import os
from os.path import dirname, abspath, join
from authkit.permissions import UserIn
from authkit.authorize import authorize

from ndg.security.server.wsgi.utils.sessionmanagerclient import \
    WSGISessionManagerClient
from ndg.security.server.wsgi.utils.attributeauthorityclient import \
    WSGIAttributeAuthorityClient


class HTTPBasicAuthentication(object):
    '''Enable Authkit based HTTP Basic Authentication for test methods'''
    def __init__(self):
        self._userIn = UserIn([])
        
    def __call__(self, environ, username, password):
        """validation function"""
        try:
            client = WSGISessionManagerClient(environ=environ,
                                    environKeyName=self.sessionManagerFilterID)
            res = client.connect(username, passphrase=password)

            if username not in self._userIn.users:
                self._userIn.users += [username]
            
            # Keep a reference to the session ID for test purposes
            environ[client.environKeyName+'.user'] = res[-1]
                
        except Exception, e:
            return False
        else:
            return True

class CombinedServicesWSGI(object):
    method = {
"/": 'default',
"/test_localSessionManagerConnect": "test_localSessionManagerConnect",
"/test_localSessionManagerGetSessionStatus": "test_localSessionManagerGetSessionStatus",
"/test_localSessionManagerDisconnect": "test_localSessionManagerDisconnect",
"/test_localSessionManagerGetAttCert": "test_localSessionManagerGetAttCert",
"/test_localAttributeAuthorityGetHostInfo": "test_localAttributeAuthorityGetHostInfo",
"/test_localAttributeAuthorityGetTrustedHostInfo": "test_localAttributeAuthorityGetTrustedHostInfo",
"/test_localAttributeAuthorityGetAllHostsInfo": "test_localAttributeAuthorityGetAllHostsInfo",
"/test_localAttributeAuthorityGetAttCert": "test_localAttributeAuthorityGetAttCert"
    }
    httpBasicAuthentication = HTTPBasicAuthentication()

    def __init__(self, app, globalConfig, **localConfig):
        self.app = app
        self.sessionManagerFilterID = localConfig.get('sessionManagerFilterID')
        self.attributeAuthorityFilterID = \
                                localConfig.get('attributeAuthorityFilterID')
                                
        CombinedServicesWSGI.httpBasicAuthentication.sessionManagerFilterID = \
            self.sessionManagerFilterID
            
    def __call__(self, environ, start_response):
        
        methodName = self.method.get(environ['PATH_INFO'], '').rstrip()
        if methodName:
            action = getattr(self, methodName)
            return action(environ, start_response)
        elif self.app is not None:
            return self.app(environ, start_response)
        else:
            start_response('404 Not Found', [('Content-type', 'text/plain')])
            return "NDG Security Combined Services Unit tests: invalid URI"
            
    def default(self, environ, start_response):
        start_response('200 OK', [('Content-type', 'text/plain')])
        return "NDG Security Combined Services Unit Tests"

    @authorize(httpBasicAuthentication._userIn)
    def test_localSessionManagerConnect(self, environ, start_response):
        start_response('200 OK', [('Content-type', 'text/plain')])
        return "test_localSessionManagerConnect succeeded"
        
    @authorize(httpBasicAuthentication._userIn)
    def test_localSessionManagerGetSessionStatus(self, environ,start_response):
        client = WSGISessionManagerClient(environ=environ,
                                    environKeyName=self.sessionManagerFilterID)
        stat=client.getSessionStatus(
                                sessID=environ[client.environKeyName+'.user'])
        start_response('200 OK', [('Content-type', 'text/xml')])
        return ("test_localSessionManagerGetSessionStatus succeeded. Response "
                "= %s" % stat)

    @authorize(httpBasicAuthentication._userIn)
    def test_localSessionManagerDisconnect(self, environ, start_response):
        client = WSGISessionManagerClient(environ=environ,
                                    environKeyName=self.sessionManagerFilterID)
        client.disconnect(sessID=environ[client.environKeyName+'.user'])
        
        # Re-initialise user authentication
        CombinedServicesWSGI.httpBasicAuthentication._userIn.users = []
        start_response('200 OK', [('Content-type', 'text/plain')])
        return "test_localSessionManagerDisconnect succeeded."

    @authorize(httpBasicAuthentication._userIn)
    def test_localSessionManagerGetAttCert(self, environ, start_response):
        client = WSGISessionManagerClient(environ=environ,
            environKeyName=self.sessionManagerFilterID,
            attributeAuthorityEnvironKeyName=self.attributeAuthorityFilterID)

        attCert = client.getAttCert(
                                sessID=environ[client.environKeyName+'.user'])
        start_response('200 OK', [('Content-type', 'text/xml')])
        return str(attCert)

    def test_localAttributeAuthorityGetHostInfo(self, environ, start_response):
        client = WSGIAttributeAuthorityClient(environ=environ,
                                environKeyName=self.attributeAuthorityFilterID)
        hostInfo = client.getHostInfo()
        start_response('200 OK', [('Content-type', 'text/html')])
        return ("test_localAttributeAuthorityGetHostInfo succeeded. Response "
                "= %s" % hostInfo)

    def test_localAttributeAuthorityGetTrustedHostInfo(self, 
                                                       environ, 
                                                       start_response):
        client = WSGIAttributeAuthorityClient(environ=environ,
                                environKeyName=self.attributeAuthorityFilterID)
        role = environ.get('QUERY_STRING', '').split('=')[-1] or None
        hostInfo = client.getTrustedHostInfo(role=role)
        start_response('200 OK', [('Content-type', 'text/html')])
        return ("test_localAttributeAuthorityGetTrustedHostInfo succeeded. "
                "Response = %s" % hostInfo)

    def test_localAttributeAuthorityGetAllHostsInfo(self, 
                                                    environ, 
                                                    start_response):
        client = WSGIAttributeAuthorityClient(environ=environ,
                                environKeyName=self.attributeAuthorityFilterID)
        hostInfo = client.getAllHostsInfo()
        start_response('200 OK', [('Content-type', 'text/html')])
        return ("test_localAttributeAuthorityGetAllHostsInfo succeeded. "
                "Response = %s" % hostInfo)

    @authorize(httpBasicAuthentication._userIn)
    def test_localAttributeAuthorityGetAttCert(self, environ, start_response):
        
        client = WSGIAttributeAuthorityClient(environ=environ,
                                environKeyName=self.attributeAuthorityFilterID)
        username=CombinedServicesWSGI.httpBasicAuthentication._userIn.users[-1]
        
        attCert = client.getAttCert(userId=username)
        start_response('200 OK', [('Content-type', 'text/xml')])
        return str(attCert)

def app_factory(globalConfig, **localConfig):
    return CombinedServicesWSGI(None, globalConfig, **localConfig)

def filter_app_factory(app, globalConfig, **localConfig):
    return CombinedServicesWSGI(app, globalConfig, **localConfig)

    
from ndg.security.test.unit import BaseTestCase

# Initialize environment for unit tests
if BaseTestCase.configDirEnvVarName not in os.environ:
    os.environ[BaseTestCase.configDirEnvVarName] = \
                            join(dirname(abspath(dirname(__file__))), 'config')

# Initialize environment for unit tests
if 'NDGSEC_COMBINED_SRVS_UNITTEST_DIR' not in os.environ:
    os.environ['NDGSEC_COMBINED_SRVS_UNITTEST_DIR']=abspath(dirname(__file__))
    
# To start run 
# $ paster serve services.ini or run this file as a script
# $ ./serverapp.py [port #]
if __name__ == '__main__':
    import sys
    import logging
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 8000
        
    cfgFilePath = os.path.join(dirname(abspath(__file__)), 'services.ini')
        
    from paste.httpserver import serve
    from paste.deploy import loadapp
    
    app = loadapp('config:%s' % cfgFilePath)
    serve(app, host='0.0.0.0', port=port)