'''
Created on May 28, 2012

@author: philipkershaw
'''
import unittest

from myproxy.ws.client import MyProxyWSClient
from myproxy.ws.test import test_ca_dir

class TestWSClient(unittest.TestCase):
    def test_logon(self):
        myproxy_client = MyProxyWSClient()
        myproxy_client.ca_cert_dir = test_ca_dir
        
        myproxy_server_url = 'https://myproxy.ceda.ac.uk/logon'
        username = 'pjkersha'
        password = ''
        res = myproxy_client.logon(username, password, myproxy_server_url)
        self.assert_(res)