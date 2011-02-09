"""NDG Gatekeeper Web service server side interface.  Generated and 
adapted from:

wsdl2dispatch -f gatekeeper.wsdl

NERC Data Grid Project

P J Kershaw 19/05/06

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
reposID = '$Id$'

from gatekeeper_services import *
from ZSI.ServiceContainer import ServiceSOAPBinding

from NDG.Gatekeeper import *


class gatekeeper(ServiceSOAPBinding):
    soapAction = {
        'urn:gatekeeper#executeAccess': 'soap_executeAccess',
        'urn:gatekeeper#readAccess': 'soap_readAccess',
        'urn:gatekeeper#writeAccess': 'soap_writeAccess',
        }

    def __init__(self, srv, debug=False, post='/gatekeeper.wsdl', **kw):
        ServiceSOAPBinding.__init__(self, post)
        
        if not isinstance(srv, Gatekeeper):
            raise GatekeeperError("Expecting NDG Gatekeeper type object")
            
        self.__srv = srv        
        self.__debug = debug


    def soap_executeAccess(self, ps):
        """Make a request for execute access to resource using an 
        Attribute Certificate"""

        if self.__debug:
            import pdb
            pdb.set_trace()        
        
        # input vals in request object
        reqArgs = ps.Parse(executeAccessRequestWrapper)        

        # assign return values to response object
        response = executeAccessResponseWrapper()
        
        response._matchingRole = ''
        response._errMsg = ''
        
        try:            
            attCert = AttCertParse(reqArgs._attCert)
            
            # Access method returns a dictionary of boolean access flags
            # keyed by role name.  Find the first where access is True
            # and return the corresponding role
            for role, bAccess in self.__srv.executeAccess(attCert).items():                
                if bAccess: 
                    response._matchingRole = role
                    break
                
        except Exception, e:
            response._errMsg = str(e)
     
        return response


    def soap_readAccess(self, ps):
        """Make a request for execute access to resource using an 
        Attribute Certificate"""

        if self.__debug:
            import pdb
            pdb.set_trace()        
        
        # input vals in request object
        reqArgs = ps.Parse(readAccessRequestWrapper)        

        # assign return values to response object
        response = readAccessResponseWrapper()
        
        response._matchingRole = ''
        response._errMsg = ''
        
        try:            
            attCert = AttCertParse(reqArgs._attCert)
            
            # Access method returns a dictionary of boolean access flags
            # keyed by role name.  Find the first where access is True
            # and return the corresponding role
            for role, bAccess in self.__srv.readAccess(attCert).items():                
                if bAccess: 
                    response._matchingRole = role
                    break
                
        except Exception, e:
            response._errMsg = str(e)
     
        return response
            
            
    def soap_writeAccess(self, ps):
        """Make a request for write access to resource using an 
        Attribute Certificate"""

        if self.__debug:
            import pdb
            pdb.set_trace()        
        
        # input vals in request object
        reqArgs = ps.Parse(writeAccessRequestWrapper)        

        # assign return values to response object
        response = writeAccessResponseWrapper()
        
        response._matchingRole = ''
        response._errMsg = ''
        
        try:            
            attCert = AttCertParse(reqArgs._attCert)
            
            # Access method returns a dictionary of boolean access flags
            # keyed by role name.  Find the first where access is True
            # and return the corresponding role
            for role, bAccess in self.__srv.writeAccess(attCert).items():                
                if bAccess: 
                    response._matchingRole = role
                    break
                
        except Exception, e:
            response._errMsg = str(e)
         
        return response
        