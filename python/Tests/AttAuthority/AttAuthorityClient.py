#!/usr/bin/env python
#from twisted.python import log
#from twisted.internet import reactor

from AttAuthority_services import AttAuthorityServiceLocator

def main(**kw):
    locator = AttAuthorityServiceLocator()
    port = locator.getAttAuthority(**kw)
    import pdb;pdb.set_trace()
    attCert = port.getAttCert("USER CERT")
    print "attCert = %s" % attCert
    
    # Factory METHOD Just guessing here
    #response = port.create(CLIENT.CreateRequest())
    #kw['endPointReference'] = response._EndpointReference
    #iport = locator.getAttAuthority(**kw)
#    reactor.stop()


if __name__ == '__main__':
    main(url="http://127.0.0.1:5700/AttributeAuthority")
#    op = GetBasicOptParser()
#    (options, args) = op.parse_args()
#    
#    SetUp(options)
#    kw = GetPortKWArgs(options)
#    reactor.callWhenRunning(main, **kw)
#    reactor.run()
