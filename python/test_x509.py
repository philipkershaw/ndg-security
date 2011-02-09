#!/usr/bin/env python
from M2Crypto import X509
from X500DN import X500DN
#
# can we easily extract the public key from an X509 certificate?
#
def handle(cert):
    issuer=cert.get_issuer()
    holder=cert.get_subject()
    print issuer
    print holder
    print 'Validity: from ',cert.get_not_before(),' to ',cert.get_not_after()
    #print dir(cert)
    x=cert.get_pubkey()

    x=X500DN(x509m2=holder)
    

def xmlplay(doc,cert):
    pass

if __name__=="__main__":
    import sys
    #usage test_x509 certfile privateKey xmlfile
    #certfile,privateKey,xmlfile=sys.argv[1],sys.argv[2],sys.argv[3]
    certfile=sys.argv[1]
    cert=X509.load_cert(certfile)
    pubkey=handle(cert)
    #xmlplay(xmlfile,cert)
