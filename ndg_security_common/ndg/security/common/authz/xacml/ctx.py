"""XACML Context Module

NERC DataGrid Project

This code is adapted from the Sun Java XACML implementation ...

Copyright 2004 Sun Microsystems, Inc. All Rights Reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistribution of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistribution in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

Neither the name of Sun Microsystems, Inc. or the names of contributors may
be used to endorse or promote products derived from this software without
specific prior written permission.

This software is provided "AS IS," without a warranty of any kind. ALL
EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES, INCLUDING
ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
OR NON-INFRINGEMENT, ARE HEREBY EXCLUDED. SUN MICROSYSTEMS, INC. ("SUN")
AND ITS LICENSORS SHALL NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE
AS A RESULT OF USING, MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS
DERIVATIVES. IN NO EVENT WILL SUN OR ITS LICENSORS BE LIABLE FOR ANY LOST
REVENUE, PROFIT OR DATA, OR FOR DIRECT, INDIRECT, SPECIAL, CONSEQUENTIAL,
INCIDENTAL OR PUNITIVE DAMAGES, HOWEVER CAUSED AND REGARDLESS OF THE THEORY
OF LIABILITY, ARISING OUT OF THE USE OF OR INABILITY TO USE THIS SOFTWARE,
EVEN IF SUN HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

You acknowledge that this software is not designed or intended for use in
the design, construction, operation or maintenance of any nuclear facility.
"""
__author__ = "P J Kershaw"
__date__ = "12/06/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"

import logging
log = logging.getLogger(__name__)

from ndg.security.common.utils.etree import QName
from ndg.security.common.authz.xacml import ParsingException

class Result(object):
    '''Represents the ResultType XML object from the Context schema. Any number
    of these may included in a <code>ResponseCtx</code>. This class encodes the
    decision effect, as well as an optional resource identifier and optional
    status data. Any number of obligations may also be included.
    '''

    # The decision to permit the request 
    validDecisions = range(4)
    (DECISION_PERMIT, 
     DECISION_DENY, 
     DECISION_INDETERMINATE, 
     DECISION_NOT_APPLICABLE) = validDecisions

        # string versions of the 4 Decision types used for encoding
    DECISIONS =  ("Permit", "Deny", "Indeterminate", "NotApplicable")

    def __init__(self, decision, status=None, resource=None, obligations=[]):
        '''Constructs Result object 
        
        @param decision: the decision effect to include in this result. This
                        must be one of the four fields in this class.
        @param status: the Status to include in this result
        @param resource: a string naming the resource
        @param obligations: the obligations the PEP must handle
        @raise TypeError: if decision is not valid
        '''
        # check that decision is valid
        if decision not in Result.validDecisions:
            raise TypeError("invalid decision value: %r" % decision)

        self.decision = decision
        self.resource = resource

        if status is None:
            self.status = Status.getOkInstance()
        else:
            self.status = status

        self.obligations = obligations
        
    @classmethod
    def getInstance(cls, root):
        decision = -1
        status = None
        resource = None
        obligations = None

        resource = root.attrib.get("ResourceId")

        for elem in root:
            name = QName.getLocalPart(elem.tag)
            if name == "Decision":
                try: 
                    decision = [i for i in Result.DECISIONS 
                                if i == elem.text][0]
                except TypeError:
                    raise ParsingException("Unknown Decision: %s" % elem.text)
                
            elif name == "Status":
                status = Status.getInstance(elem)
                
            elif name == "Obligations": 
                obligations = self.parseObligations(elem)

        return Result(decision, status=status, resource=resource, 
                      obligations=obligations)

    def parseObligations(self, root):
        '''Helper method that handles the obligations'''
        obligationSet = []

        for elem in root:
            if QName.getLocalPart(elem.tag) == "Obligation":
                obligationSet.append(Obligation.getInstance(node))
        
        if len(obligationSet) == 0:
            raise ParsingException("ObligationsType must not be empty")
        
        return obligationSet
    
    def encode(self, output, indenter=None):
        '''Encodes this <code>Result</code> into its XML form and writes this
        out to the provided output stream with no indentation.
        
        @param output: a stream into which the XML-encoded data is written
        @param indenter: an object that creates indentation strings'''
        raise NotImplementedError()

