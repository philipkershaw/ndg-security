#!/usr/bin/env python
"""SOAP module unit test module

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "24/07/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
logging.basicConfig(level=logging.DEBUG)

import unittest
from cStringIO import StringIO
import paste.fixture
from urllib2 import HTTPHandler, URLError

from ndg.security.test.unit import BaseTestCase
from ndg.security.common.soap.etree import SOAPEnvelope
from ndg.security.common.soap.client import UrlLib2SOAPClient, \
    UrlLib2SOAPRequest

class SOAPBindingMiddleware(object):
    """Simple WSGI interface for SOAP service"""
        
    def __call__(self, environ, start_response):
        requestFile = environ['wsgi.input']
        
        print("Server received request from client:\n\n%s" % 
              requestFile.read())
        
        soapResponse = SOAPEnvelope()
        soapResponse.create()
        
        response = soapResponse.serialize()
        start_response("200 OK",
                       [('Content-length', str(len(response))),
                        ('Content-type', 'text/xml')])
        return [response]
    
    
class SOAPTestCase(BaseTestCase):
    SOAP_SERVICE_PORTNUM = 10080
    ENDPOINT = 'http://localhost:%d/soap' % SOAP_SERVICE_PORTNUM
    
    def __init__(self, *args, **kwargs):
        """Use paste.fixture to test client/server SOAP interface"""
        wsgiApp = SOAPBindingMiddleware()
        self.app = paste.fixture.TestApp(wsgiApp)
         
        super(SOAPTestCase, self).__init__(*args, **kwargs)
        
    def test01Envelope(self):
        envelope = SOAPEnvelope()
        envelope.create()
        soap = envelope.serialize()
        
        self.assert_(len(soap) > 0)
        self.assert_("Envelope" in soap)
        self.assert_("Body" in soap)
        self.assert_("SOAP-ENV:Header" in soap)
        
        print(envelope.prettyPrint())
        stream = StringIO()
        stream.write(soap)
        stream.seek(0)
        
        envelope2 = SOAPEnvelope()
        envelope2.parse(stream)
        soap2 = envelope2.serialize()
        self.assert_(soap2 == soap)

    def test02SendRequest(self):
        requestEnvelope = SOAPEnvelope()
        requestEnvelope.create()
        request = requestEnvelope.serialize()
        
        response = self.app.post('/my-soap-endpoint', 
                                 params=request, 
                                 status=200)
        print(response.headers)
        print(response.status)
        print(response.body)

    def test03Urllib2Client(self):
        
        # Paster based service is threaded from this call
        self.addService(app=SOAPBindingMiddleware(), 
                        port=SOAPTestCase.SOAP_SERVICE_PORTNUM)
        
        client = UrlLib2SOAPClient()
        
        # ElementTree based envelope class
        client.responseEnvelopeClass = SOAPEnvelope
        
        request = UrlLib2SOAPRequest()
        request.url = SOAPTestCase.ENDPOINT
        request.envelope = SOAPEnvelope()
        request.envelope.create()
        
        client.openerDirector.add_handler(HTTPHandler())
        try:
            response = client.send(request)
        except URLError, e:
            self.fail("soap_server.py must be running for this test")
        
        print("Response from server:\n\n%s" % response.envelope.serialize())

if __name__ == "__main__":
    unittest.main()