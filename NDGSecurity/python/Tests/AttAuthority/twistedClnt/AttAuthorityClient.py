#!/usr/bin/env python
from twisted.python import log
from twisted.internet import reactor

import sys

from ndg.security.common.zsi.attributeauthority.AttributeAuthority_services import AttributeAuthorityServiceLocator

def main(**kw):
    locator = AttributeAuthorityServiceLocator()
    port = locator.getAttributeAuthority(**kw)
    import pdb;pdb.set_trace()
    attCert = port.getAttCert("USER CERT")
    print "attCert = %s" % attCert
    
    # Factory METHOD Just guessing here
    #response = port.create(CLIENT.CreateRequest())
    #kw['endPointReference'] = response._EndpointReference
    #iport = locator.getAttributeAuthority(**kw)
    reactor.stop()


if __name__ == '__main__':
    kw = {'url': "http://127.0.0.1:5700/AttributeAuthority",
          'tracefile': sys.stdout}
#    op = GetBasicOptParser()
#    (options, args) = op.parse_args()
#    
#    SetUp(options)
#    kw = GetPortKWArgs(options)
    reactor.callWhenRunning(main, **kw)
    reactor.run()
