"""XACML eval module contains Evaluatable class

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
__date__ = "10/06/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
import logging
log = logging.getLogger(__name__)

     
class EvaluationResult(object):
    def __init__(self, 
                 attributeValue=None, 
                 status=None, 
                 indeterminate=False):
        self.status = status
        self.attributeValue = attributeValue
        self.indeterminate = indeterminate
        
        
class Evaluatable(object):
    '''Generic interface that is implemented by all objects that can appear in
    an ApplyType. This lets the evaluation code of Apply and
    functions iterate through their members and evaluate them, working only
    on the returned values or errors.'''
    
    def evaluate(self, context):
        '''Evaluates the object using the given context, and either returns an
        error or a resulting value.
    
        @param context the representation of the request
        @return the result of evaluation'''
        raise NotImplementedError()

    def getType(self):
        '''Get the type of this object.  This may be the data type of an
        Attribute or the return type of an
        AttributeDesignator, etc.
    
        @return the type of data represented by this object'''
        raise NotImplementedError()

    def evaluatesToBag(self):
        '''Tells whether evaluation will return a bag or a single value.
    
        @return true if evaluation will return a bag, false otherwise'''
        raise NotImplementedError()

    def getChildren(self):
        '''Returns all children, in order, of this element in the Condition
        tree, or en empty set if this element has no children. In XACML 1.x,
        only the ApplyType ever has children.
    
        @return a list of Evaluatables'''
        raise NotImplementedError()

    def encode(self, output, indenter=None):
        '''Encodes this Evaluatable into its XML representation and
        writes this encoding to the given OutputStream with
        indentation.
    
        @param output a stream into which the XML-encoded data is written
        @param indenter an object that creates indentation strings'''
        raise NotImplementedError()
