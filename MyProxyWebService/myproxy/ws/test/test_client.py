'''
Created on May 28, 2012

@author: philipkershaw
'''
import unittest

from myproxy.ws.client import MyProxyWSClient
from myproxy.ws.test import test_ca_dir

class WSClientTestCase(unittest.TestCase):
    """Test MyProxy Web Service Client"""
    
    def test_logon(self):
        myproxy_client = MyProxyWSClient()
        myproxy_client.ca_cert_dir = test_ca_dir
        
        myproxy_server_url = 'https://localhost/logon'
        username = 'testuser'
        password = ''
        res = myproxy_client.logon(username, password, myproxy_server_url)
        self.assert_(res)