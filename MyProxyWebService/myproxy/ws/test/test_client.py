'''
Created on May 28, 2012

@author: philipkershaw
'''
import unittest

from myproxy.ws.client import MyProxyWSClient


class TestWSClient(unittest.TestCase):
    def test_logon(self):
        myproxy_client = MyProxyWSClient()
        
        myproxy_server_url = ''
        username = ''
        password = ''
        res = myproxy_client.logon(username, password, myproxy_server_url)
        self.assert_(res)