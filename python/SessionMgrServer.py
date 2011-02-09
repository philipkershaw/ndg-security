#!/usr/bin/env python

"""NDG Session Manager Web Services server interface

NERC Data Grid Project

P J Kershaw 16/08/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

cvsID = '$Id$'

# Handle socket errors from WS
import socket 

# Web service interface
from ZSI import dispatch
from NDG.sessionMgr_services import *

# Command line processing
import sys
import os
import getopt

# Session Manager
from NDG.Session import *




def addUser(userName, passPhrase):
    """NDG Session Manager WS interface for the creation of a new user account
    """
    
    if debug:
        import pdb
        pdb.set_trace()

    resp = addUserResponseWrapper()
    resp._errMsg = ''
        
    # Request a new session from the Session Manager
    try:
        userSess = sm.addUser(str(userName), str(passPhrase))
        
    except Exception, e:
        resp._errMsg = str(e)
    
    return resp




def connect(userName, passPhrase, rtnAsCookie):
    """NDG Session Manager WS interface for connection to a user session."""
    
    if debug:
        import pdb
        pdb.set_trace()

    resp = connectResponseWrapper()
    resp._sessID = ''
    resp._expiry = ''
    resp._cookie = ''
    resp._errMsg = ''
        
    # Request a new session from the Session Manager
    try:
        userSess = sm.connect(userName=str(userName),
                              passPhrase=str(passPhrase))
        
        # Return the latest session ID to be allocated
        resp._sessID = userSess['sessID'][-1]
        resp._expiry = userSess.getExpiryStr()
        
        if bool(rtnAsCookie):
            resp._cookie = userSess.createCookie()
            
    except Exception, e:
        resp._errMsg = str(e)
    
    return resp




def reqAuthorisation(aaWSDL,
                     sessID,
                     reqRole,
                     mapFromTrustedHosts,
                     extAttCertList,
                     extTrustedHostList):
    """NDG Session Manager WS interface for user authorisation."""
    
    if debug:
        import pdb
        pdb.set_trace()

    resp = reqAuthorisationResponseWrapper()
    resp._attCert = ''
    resp._extAttCertList = []
    resp._statCode = 'AccessGranted'
    resp._errMsg = ''


    # Convert from default used for SOAP transfer to convention with python
    # server
    if isinstance(aaWSDL, unicode):
        aaWSDL = str(aaWSDL)

    if isinstance(sessID, unicode):
        sessID = str(sessID)

    if isinstance(reqRole, unicode):
        reqRole = str(reqRole)
        
    if isinstance(extAttCertList, list):
        # Convert from unicode
        extAttCertList = [str(attCert) for attCert in extAttCertList]
    else:
        # Correct default if not a list is None
        extAttCertList = None
        
    if isinstance(extTrustedHostList, list):
        # Convert from unicode
        extTrustedHostList = [str(hostName) \
                              for hostName in extTrustedHostList]
    else:
        # Correct default if not a list is None
        extTrustedHostList = None
        
    
    # Request a new attribute certificate from the Session Manager
    try:
        attCert = sm.reqAuthorisation(\
                                aaWSDL=aaWSDL,
                                sessID=sessID,
                                reqRole=reqRole,
                                bMapFromTrustedHosts=bool(mapFromTrustedHosts),
                                bSetExtAttCertList=True,
                                extAttCertList=extAttCertList,
                                extTrustedHostList=extTrustedHostList)
        
        resp._attCert = attCert.asString()

    except SessionMgrAuthorisationDenied, e:
        resp._statCode = 'AccessDenied'
        resp._errMsg = str(e)
        resp._extAttCertList = [attCert.asString() for attCert in \
                                e['extAttCertList']]
        
    except Exception, e:
        resp._statCode = 'AccessError'
        resp._errMsg = str(e)
    
    return resp




def usage():
    """Describes how to call SessionMgrServer from the command line"""
    print "usage: %s " % sys.argv[0].split(os.sep)[-1]
    print """    
[-h | --help]
    print usage summary
    
[-f <properties file path> | --file=<properties file path>]

[-p <port #> | --port=<port #>]
    port number for server to listen on

[-d | --debug]
    set to stop in debugger on receipt of WS request
    
[-n | --nopassphrase]
    skip the prompt for the database pass-phrase.  In this case, the
    pass-phrase must be set in the dbURI in the configuration file.
"""




if __name__ == '__main__':

    try:
        optLongNames = ["help", "file=", "port=", "debug", "nopassphrase"]
        opts, args = getopt.getopt(sys.argv[1:], "hf:p:dn", optLongNames)
        
    except getopt.GetoptError:
        usage()
        sys.exit(1)


    propFilePath = None
    port = 5700 #80 # temporary port for testing
    debug = False
    noPPhrase = False
    
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()                     
            sys.exit(0)
            
        elif opt in ("-d", "--debug"):
            debug = True
            
        elif opt in ("-f", "--file"):
            propFilePath = arg

        elif opt in ("-p", "--port"):
            port = int(arg)

        elif opt in ("-n", "--nopassphrase"):
            noPPhrase = True


    if propFilePath is None:
        # Check in installation area otherwise assume local directory
        if 'NDG_DIR' in os.environ:
            propFileDir = os.path.join(os.environ['NDG_DIR'], "conf")
        else:
            propFileDir = "."

        propFilePath = os.path.join(propFileDir, 'sessionMgrProperties.xml')


    if noPPhrase is False:
        import getpass
        try:
            credReposPPhrase = getpass.getpass(\
                                prompt="Credential Repository pass-phrase: ")
        except KeyboardInterrupt:
            sys.exit(0)
    else:
        credReposPPhrase = None
        

    # Create server instance at start up
    try:
        sm = SessionMgr(propFilePath, credReposPPhrase=credReposPPhrase)
        
    except Exception, e:
        sys.stderr.write("Initialising Session Manager: %s\n" % e)
        sys.exit(1)
    
    print "Session Manager Server listening..."
    try:
        dispatch.AsServer(port=port)

    except KeyboardInterrupt:
        sys.exit(0)

    except socket.error, e:
        sys.stderr.write("Session Manager Server socket error: %s\n" % \
                         e[1])
        sys.exit(1)

    except Exception, e:
        sys.stderr.write("Session Manager Server: %s\n" % e)
        sys.exit(1)
        
