'''
Created on May 13, 2011

@author: philipkershaw
'''
import unittest

import beaker
import paste.fixture
from ndg.security.server.wsgi.client_proxy.middleware import (NDGSecurityProxy,
                                        MyProxyProvisionedSessionMiddleware)


class Test(unittest.TestCase):


    def test01(self):
        app = NDGSecurityProxy('localhost')
        app = MyProxyProvisionedSessionMiddleware(app)
        app = beaker.
        app = paste.fixture.TestApp(app)
        
        response = app.get('/')
        self.assert_(response)
        print(response)
    
#    def test02fromIniFile(self):
#        here_dir = os.path.dirname(os.path.abspath(__file__))
#        app = loadapp('config:test.ini', relative_to=here_dir)
#        self.app = paste.fixture.TestApp(app)
#        
#        response = self.app.get('/')
#        self.assert_(response) 
#        print(response)      


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()