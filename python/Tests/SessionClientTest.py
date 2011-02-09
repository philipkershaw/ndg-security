#!/usr/bin/env python

"""Test harness for NDG Session client - makes requests for authentication and
authorisation

NERC Data Grid Project

P J Kershaw 23/02/06

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
import os
from Cookie import SimpleCookie

from NDG.SessionClient import *


#_____________________________________________________________________________
if __name__ == '__main__':

    # Set -d on command line to run in debug mode
    if len(sys.argv) > 1 and sys.argv[1] == '-d':
        import pdb
        pdb.set_trace()

    try:
        # Modify settings as required for tests...
        
        # Attribute Authority WSDL      
        aaWSDL = 'http://.../attAuthority.wsdl'
        
        # Session Manager WSDL
        smWSDL = 'http://.../sessionMgr.wsdl'
        #smWSDL = 'http://gabriel.bnsc.rl.ac.uk/sessionMgr.wsdl'

        # Public key of session manager used to encrypt requests
        smEncrPubKeyFilePath = \
            os.path.expandvars("$NDG_DIR/conf/certs/<name>-sm-cert.pem")
        #smEncrPubKeyFilePath = None
        
        #
        # If no public key is set, requests will be made in clear text without
        # encryption!
        #smEncrPubKeyFilePath = None
        
        # User ID to register with NDG MyProxy OR an existing ID to connect
        #userName = 'gabriel'
        userName = 'a.n.other@somewhere.ac.uk'

        # Initialise the Session Manager client connection
        # Omit traceFile keyword to leave out SOAP debug info
        sessClnt = SessionClient(smWSDL=smWSDL,
                                 smEncrPubKeyFilePath=smEncrPubKeyFilePath,
                                 traceFile=sys.stderr)

        # Uncomment to add a new user ID to the MyProxy repository
        # Note the pass-phrase is read from the file tmp.txt.  To pass
        # explicitly as a string use the 'pPhrase' keyword instead
#        sessClnt.addUser(userName, pPhraseFilePath="./tmp")
#        print "Added user '%s'" % userName
        
        # Connect using an existing user ID or using the one just created 
        # above
        #
        # Connect as if acting as a browser client - a cookie is returned
#        sSessCookie = sessClnt.connect(userName, pPhraseFilePath="./tmp")
#        sessCookie = SimpleCookie(sSessCookie)
#        print "User '%s' connected to Session Manager" % userName
#
#        # Request an attribute certificate from an Attribute Authority using 
#        # the cookie returned from connect()
#        authResp = sessClnt.reqAuthorisation(
#                            sessID=sessCookie['NDG-ID1'].value, 
#                            encrSessMgrWSDLuri=sessCookie['NDG-ID2'].value,
#                            aaWSDL=aaWSDL)

        proxyCert = sessClnt.connect(userName, 
                                     pPhraseFilePath="./tmp",
                                     createServerSess=True,
                                     getCookie=False)
        print "User '%s' connected to Session Manager" % userName

        # Request an attribute certificate from an Attribute Authority using 
        # the cookie returned from connect()
        authResp = sessClnt.reqAuthorisation(proxyCert=proxyCert,
                                             aaWSDL=aaWSDL)
                                             
        # The authorisation response is returned as an object which behaves
        # like a python dictionary.  See NDG.SessionMgrIO.AuthorisationResp
        if 'errMsg' in authResp:
            print "Authorisation failed for user '%s':\n" % userName            
        else:
            print "User '%s' authorised:\n" % userName
            
        print authResp
        sys.exit(0)
        
    except Exception, e:
        sys.stderr.write(str(e) + os.linesep)
        sys.exit(1)
        
