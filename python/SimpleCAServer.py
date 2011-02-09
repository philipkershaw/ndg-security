#!/usr/bin/env python

"""NDG Attribute Authority Web Services server interface

NERC Data Grid Project

P J Kershaw 02/08/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

cvsID = '$Id$'

# Handle socket errors from WS
import socket 

from ZSI import dispatch
from NDG.simpleCA_services import reqCertResponseWrapper
import sys
from NDG.SimpleCA import *

# Certificate request is a class to encapsulate digital signature handling
from NDG.CertReq import *

# Command line processing
import sys
import os
import getopt


def reqCert(usrCertReq):

    """NDG SimpleCA WS interface for certificate request."""
    
    resp = reqCertResponseWrapper()
    resp._usrCert = ''
    resp._errMsg = ''

    if debug:
        import pdb
        pdb.set_trace()     

    # Check digital signature
    #
    # Nb. Ensure string is converted from unicode
    try:
        certReq = CertReqParse(str(usrCertReq),
                               certFilePathList=simpleCA['caCertFile'])

        if not certReq.isValidSig():
            raise Exception("signature for request message is invalid")
        
    except Exception, e:
        resp._errMsg = "Certificate request: %s" % str(e)
        return resp

    
    # Request a new X.509 certificate from the CA
    try:
        resp._usrCert = simpleCA.sign(certReq.sCertReq)
        
    except Exception, e:
        resp._errMsg = "New certificate: %s" % str(e)
    
    return resp




def usage():
    """Describes how to call SimpleCAServer from the command line"""
    print "usage: %s " % sys.argv[0].split(os.sep)[-1]
    print """    
[-h | --help]
    print usage summary
    
[-f <properties file path> | --file=<properties file path>]
    path to properties file.  If not set, defaults to
    $NDG_DIR/conf/simpleCAProperties.xml
    
[-c <configuration file path> | --conf=<configuration file path>]
    path to configuration file.  If not set, user is prompted for input.

[-p <port #> | --port=<port #>
    port number for server to listen on

[-d | --debug]
    set to stop in debugger on receipt of WS request
"""




if __name__ == '__main__':

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "hf:c:p:d",
                                   ["help","file=","conf=","port=","debug"])        
    except getopt.GetoptError:
        usage()
        sys.exit(1)


    propFilePath = None
    configFilePath = None
    port = 5500 #80 # temporary port for testing
    debug = False
    
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()                     
            sys.exit(0)
            
        elif opt in ("-d", "--debug"):
            debug = True
            
        elif opt in ("-f", "--file"):
            propFilePath = arg
            
        elif opt in ("-c", "--conf"):
            configFilePath = arg

        elif opt in ("-p", "--port"):
            port = int(arg)

            
    if propFilePath is None:
        # Check in installation area otherwise assume local directory
        if 'NDG_DIR' in os.environ:
            propFileDir = os.path.join(os.environ['NDG_DIR'], "conf")
        else:
            propFileDir = "."

        propFilePath = os.path.join(propFileDir, 'simpleCAProperties.xml')


    # If no configuration file path is provided, read from stdin
    if configFilePath is None:
        import getpass
        configTxt = getpass.getpass(prompt="SimpleCA Passphrase: ")

        
    # Create server instance at start up
    try:
        simpleCA = SimpleCA(propFilePath, configFilePath, configTxt)
        
    except Exception, e:
        sys.stderr.write("Initialising SimpleCA: %s\n" % e)
        sys.exit(1)
    
    print "SimpleCA Server listening..."
    try:
        dispatch.AsServer(port=port)

    except KeyboardInterrupt:
        sys.exit(0)

    except socket.error, e:
        sys.stderr.write("SimpleCA Server socket error: %s\n" % \
                         e[1])
        sys.exit(1)

    except Exception, e:
        sys.stderr.write("SimpleCA Server: %s\n" % e)
        sys.exit(1)
