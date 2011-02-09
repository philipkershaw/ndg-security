#!/usr/bin/env python

"""NDG Attribute Authority Web Services server interface

NERC Data Grid Project

P J Kershaw 05/05/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

cvsID = '$Id$'

# Handle socket errors from WS
import socket 

# Web service interface
from ZSI import dispatch
from NDG.attAuthority_services import *

# Command line processing
import sys
import os
import getopt

# Attribute Authority
from NDG.AttAuthority import *


def getTrustedHostInfo(usrRole):
    """NDG Attribute Authority WS interface - return the trusted hosts for
    the given input role."""
    
    if debug:
        import pdb
        pdb.set_trace()

    resp = getTrustedHostInfoResponseWrapper()
    resp._trustedHostInfo = []
    resp._errMsg = ''


    # Prevent WS client making a call with no role provided.  This would
    # normally return a list of all the trusted hosts for the AA and the
    # associated roles.  Disallow this for extra security
    if usrRole == '' or usrRole is None:
        resp._errMsg = "No role was input"
        return resp

    
    # Request a new attribute certificate from the Attribute Authority
    try:
        # Output is a dictionary of roles indexed by host name
        trustedHostInfo = aa.getTrustedHostInfo(str(usrRole))      
        if trustedHostInfo is not None:
            # Serialise dictionary output
            resp._trustedHostInfo = ["%s:%s:%s" % \
                                  (i[0],i[1]['wsdl'],', '.join(i[1]['role']))\
                                  for i in trustedHostInfo.items()]
        
    except Exception, e:
        resp._errMsg = str(e)
    
    return resp




def reqAuthorisation(usrProxyCert, usrAttCert):
    """NDG Attribute Authority WS interface for user authorisation."""
    
    if debug:
        import pdb
        pdb.set_trace()

    resp = reqAuthorisationResponseWrapper()
    resp._attCert = ''
    resp._statCode = 'AccessGranted'
    resp._errMsg = ''

    # Passing usrAttCert as None causes an error with ZSI, use '' instead and
    # convert to None for input into AttAuthority
    if usrAttCert == '':
        usrAttCert = None
        
    # Request a new attribute certificate from the Attribute Authority
    try:
        resp._attCert = aa.authorise(usrProxyCertFileTxt=usrProxyCert,
                                      extAttCertFileTxt=usrAttCert)
    except AttAuthorityAccessDenied, e:
        resp._statCode = 'AccessDenied'
        resp._errMsg = str(e)
        
    except Exception, e:
        resp._statCode = 'AccessError'
        resp._errMsg = str(e)
    
    return resp




def usage():
    """Describes how to call AttAuthorityServer from the command line"""
    print "usage: %s " % sys.argv[0].split(os.sep)[-1]
    print """    
[-h | --help]
    print usage summary
    
[-f <properties file path> | --file=<properties file path>]

[-p <port #> | --port=<port #>
    specify a port number to override the default
    
[-d | --debug]
    set to stop in debugger on receipt of WS request
"""




if __name__ == '__main__':

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "hf:p:d",
                                   ["help", "file=", "port=", "debug"])        
    except getopt.GetoptError:
        usage()
        sys.exit(1)


    propFilePath = None
    port = 5000 #80 # temporary port for testing
    debug = False
    
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

    if propFilePath is None:
        # Check in installation area otherwise assume local directory
        if 'NDG_DIR' in os.environ:
            propFileDir = os.path.join(os.environ['NDG_DIR'], "conf")
        else:
            propFileDir = "."

        propFilePath = os.path.join(propFileDir, 'attAuthorityProperties.xml')

        
    # Create server instance at start up
    try:
        aa = AttAuthority(propFilePath)

    except Exception, e:
        sys.stderr.write("Initialising Attribute Authority: %s\n" % e)
        sys.exit(1)
    
    print "Attribute Authority Server listening..."
    try:
        dispatch.AsServer(port=port)

    except KeyboardInterrupt:
        sys.exit(0)

    except socket.error, e:
        sys.stderr.write("Attribute Authority Server socket error: %s\n" % \
                         e[1])
        sys.exit(1)
        
    except Exception, e:
        sys.stderr.write("Attribute Authority Server: %s\n" % e)
        sys.exit(1)
        
