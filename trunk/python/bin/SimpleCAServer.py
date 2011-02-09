#!/usr/bin/env python

"""NDG Attribute Authority Web Services server interface

NERC Data Grid Project

P J Kershaw 02/08/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

reposID = '$Id$'

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
import optparse


def reqCert(usrCertReq):

    """NDG SimpleCA WS interface for certificate request."""
    
    resp = reqCertResponseWrapper()
    resp._usrCert = ''
    resp._errMsg = ''

    if options.debug:
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
        resp._usrCert = simpleCA.sign(certReq.certReqTxt)
        
    except Exception, e:
        resp._errMsg = "New certificate: %s" % e
    
    return resp


#_____________________________________________________________________________
def runInForegnd():
    """Run Simple CA in the same process as this script"""
    
    print "Simple CA Server listening..."
    try:
         dispatch.AsServer(port=options.port)

    except KeyboardInterrupt:
        sys.exit(0)

    except socket.error, e:
        print >>sys.stderr, "Simple CA Server socket error: %s" % e[1]
        sys.exit(1)

    except Exception, e:
        print >>sys.stderr, "Simple CA Server: %s" % e
        sys.exit(1)
        

#_____________________________________________________________________________
def fork(stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
    """Run Simple CA in a separate child process
    
    Thanks to Jorgen Hermann and user contributors for fork code
    
    http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/66012
    
    """
    
    try: 
        pid = os.fork() 
        if pid > 0:
            # exit first parent
            sys.exit(0) 
    except OSError, e: 
        print >>sys.stderr, "fork #1 failed: %d (%s)" % (e.errno, e.strerror) 
        sys.exit(1)

    # Decouple from parent environment
    os.chdir("/") # Allows for current dir path being renamed or deleted
    os.setsid() 
    os.umask(0) 
    
    # Redirect standard file descriptors
    si = file(stdin, 'r')
    so = file(stdout, 'a+')
    se = file(stderr, 'a+', 0)
    
    sys.stdout.flush()
    sys.stderr.flush()

    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())
    

    # Do second fork
    try: 
        pid = os.fork() 
        if pid > 0:
            # exit from second parent
            sys.exit(pid) 
    except OSError, e: 
        print >>sys.stderr, "fork #2 failed: %d (%s)" % (e.errno, e.strerror) 
        sys.exit(1) 

    # start the daemon main loop
    try:
         dispatch.AsServer(port=options.port)

    except socket.error, e:
        print >>sys.stderr, "Simple CA Server socket error: %s" % e[1]
        sys.exit(1)

    except Exception, e:
        print >>sys.stderr, "Simple CA Server: %s" % e
        sys.exit(1)


#_____________________________________________________________________________
if __name__ == '__main__':

    parser = optparse.OptionParser()

    # Check in installation area otherwise assume local directory
    propFileDir = 'NDG_DIR' in os.environ and \
                            os.path.join(os.environ['NDG_DIR'], "conf") or "."

    propFilename = 'simpleCAProperties.xml'
    parser.add_option("-f",
                      "--file",
                      dest="propFilePath",
                      default=os.path.join(propFileDir, propFilename),
                      help=\
"""properties file path - default is $NDG_DIR/conf/%s or ./%s if NDG_DIR is
not set""" % (propFilename, propFilename))

    
    parser.add_option("-c",
                      "--conf",
                      dest="configFilePath",
                      default=None,
                      help=\
"""path to configuration file used to set CA pass-phrase.  If not set,
pass-phrase is prompted for from tty.""")


    parser.add_option("-s",
                      "--pass-phrase-from-stdin",
                      action="store_true",
                      dest="bPassPhraseFromStdin",
                      default=False,
                      help="""\
Take CA pass-phrase from stdin.  If not set, pass-phrase is prompted for from
tty.""")


    # Port may be set from an environment variable.  Note that this will be
    # overridden if the port command line argument is set 
    caPortNumEnvVarName = 'NDG_CA_PORT_NUM'
    defaultPort = 5500
    
    initPort = caPortNumEnvVarName in os.environ and \
                        int(os.environ[caPortNumEnvVarName]) or defaultPort
            
    parser.add_option("-p",
                      "--port",
                      dest="port",
                      default=initPort,
                      type="int",
                      help=\
"specify a port number - default is %d or set environment variable \"%s\"" % \
                                          (defaultPort, caPortNumEnvVarName))
    
    foregndFlags = ("-i", "--foreground")
    parser.add_option(action="store_true",
                      dest="foregndProc",
                      default=False,
                      help=\
"run server as process in the foreground.  If not set, fork a child process",
                      *foregndFlags)
    
    parser.add_option("-d",
                      "--debug",
                      action="store_true",
                      dest="debug",
                      default=False,
                      help=\
"set to stop in debugger on receipt of WS request.  %s flag must be set also"\
                                            % '/'.join(foregndFlags))
                                            
    (options, args) = parser.parse_args()

        
    # Create server instance at start up - pass in config file path in case
    # this was set on the command line
    try:
        simpleCA = SimpleCA(propFilePath=options.propFilePath,
                            configFilePath=options.configFilePath)
    except Exception, e:
        print >>sys.stderr, "Initialising Simple CA: %s" % e
        sys.exit(1)


    # Check in case pass-phrase was not set via config file option
    try:
        if options.bPassPhraseFromStdin:
            
            # Pass-phrase may be set from stdin
            try:
                simpleCA.caPassPhrase = sys.stdin.read().strip()
                
            except SimpleCAPassPhraseError, e:
                print >>sys.stderr, "Invalid pass-phrase set from stdin"
                sys.exit(1)
                    
        elif options.configFilePath is None:
            
            # No configuration file was set either - read from user input at
            # terminal
            import getpass
    
            nTries = 0
            while nTries < 10:
                try:
                    simpleCA.caPassPhrase = \
                        getpass.getpass(prompt="Simple CA Pass-phrase: ")
                    break
                
                except KeyboardInterrupt:
                    sys.exit(1)
                    
                except SimpleCAPassPhraseError, e:
                    nTries += 1
                    if nTries >= 10:
                        print >>sys.stderr, \
                            "Invalid Pass-phrase - exiting after 10 attempts"
                        sys.exit(1)
                    else:
                        print >>sys.stderr, "Invalid pass-phrase"
            
    except Exception, e:
        # Catch all
        print >>sys.stderr, "Error checking Simple CA pass-phrase: %s" % e
        sys.exit(1)
        

    if options.foregndProc:
        runInForegnd()
    else:
        if options.debug:
            print >>sys.stderr, "%s must be set with debug option" % \
                                                    '/'.join(foregndFlags)
            parser.print_help()
            sys.exit(1)
            
        
        # Set this flag to True to catch errors raised in the new process
        # in a log.  Normally stderr is re-directed to /dev/null to avoid
        # conflists with the parent process    
        logForkErr = False
        if logForkErr:
            import tempfile
            errLogH, errLogFilePath = tempfile.mkstemp(".err", 
                                                       "SimpleCAServer-")
        else:
            errLogFilePath = '/dev/null'

        # Run server in separate process
        fork(stderr=errLogFilePath)    
