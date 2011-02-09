"""XACML Package

NERC DataGrid Project

This package is adapted from the Sun Java XACML implementation ...

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
__date__ = "13/02/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"

import logging
log = logging.getLogger(__name__)

from elementtree import ElementTree
from ndg.security.common.utils.etree import QName

from ndg.xacml.exceptions import ParsingException, UnknownIdentifierException
from ndg.xacml.cond.factory import FunctionFactory, FunctionTypeException
from ndg.xacml.attr import AttributeFactory, AttributeDesignator
from ndg.xacml.ctx import Result
from ndg.xacml.cond import Apply


class XacmlBase(object):
    pass


class Subject(XacmlBase):
    '''XACML Subject designator'''
    def __init__(self, attributes={}):
        self.attributes = attributes


class Resource(XacmlBase):
    '''XACML Resource designator'''


class Action(XacmlBase):
    '''XACML Action designator'''


class Environment(XacmlBase):
    '''XACML Environment designator'''


class PolicySet(XacmlBase):
    def __init__(self):
        self.policies = []
        self.combiningAlg = None

          
class Policy(XacmlBase):

    def __init__(self,
                 id='',
                 ruleCombiningAlg=None,
                 description='',
                 target=None,
                 rules=[],
                 obligations=[]):
        self.id = id
        self.description = description
        self.rules = rules
        self.ruleCombiningAlg = ruleCombiningAlg
        self.obligations = obligations
        self.target = target

    def encode(self):
        '''Encode the policy'''
        raise NotImplemented()
    
    @classmethod
    def getInstance(cls, root=None, source=None):
        """
        @type root: ElementTree.Element
        @param root: ElementTree root element
        @type source: basestring / file like object
        @param source: file path or file like object source of data
        """
        if root is None:
            if source is None:
                raise AttributeError('"root" or "source" keywords must be '
                                     'provided')
                
            elem = ElementTree.parse(source)
            root = elem.getroot()
        
        rules = []
        for elem in root:
            localName = QName.getLocalPart(elem.tag)
            if localName == 'Description':
                description = elem.text.strip()
                
            elif localName == 'Target':
                target = Target.getInstance(elem)
                
            elif localName == 'Rule':
                rules.append(Rule.getInstance(elem))
            
        policy = cls(id=root.attrib['PolicyId'], 
                     ruleCombiningAlg=root.attrib['RuleCombiningAlgId'],
                     description=description,
                     target=target,
                     rules=rules,
                     obligations=obligations)
        return policy


class MatchResult(XacmlBase):
    pass


class Target(XacmlBase):
    '''The target selects policies relevant to a request'''

    def __init__(self, subjects=None, resources=None, actions=None):
        self.subjects = subjects
        self.resources = resources
        self.actions = actions
        self.rules = []

    def Match(self, evaluationCtx):
        return MatchResult()
        
    @classmethod
    def getInstance(cls, root):
        '''Parse a Target from a given XML ElementTree element
        '''
        subjects = None
        resources = None
        actions = None
        
        for elem in root:
            localName = QName.getLocalPart(elem.tag)

            if localName == "Subjects":
                subjects = Target._getAttributes(elem, "Subject")
                
            elif localName == "Resources":
                resources = Target._getAttributes(elem, "Resource")
                
            elif localName == "Actions":
                actions = Target._getAttributes(elem, "Action")
        
        return cls(subjects=subjects, resources=resources, actions=actions)
    
    @staticmethod
    def _getAttributes(root, prefix):
        '''Helper method to get Target children elements'''
        matches = []

        for elem in root:
            localName = QName.getLocalPart(elem.tag)

            if localName == prefix:
                matches += Target._getMatches(elem, prefix)
            elif localName == "Any" + prefix:
                return None

        return matches
    
    @staticmethod
    def _getMatches(root, prefix):

        _list = []

        for elem in root:
            localName = QName.getLocalPart(elem.tag)

            if localName == prefix + "Match":
                _list.append(TargetMatch.getInstance(elem, prefix))

        return tuple(_list)
        
    
class TargetMatch(XacmlBase):
    '''Represents the SubjectMatch, ResourceMatch, or ActionMatch XML 
    types in XACML, depending on the value of the type field. This is the 
    part of the Target that actually evaluates whether the specified 
    attribute values in the Target match the corresponding attribute 
    values in the request context.
    '''
    types = range(3)
    SUBJECT, RESOURCE, ACTION = types
    
    def __init__(self,
                 _type,
                 function,
                 _eval,
                 attributeValue):
        '''Create a TargetMatch from components.
         
        @param type an integer indicating whether this class represents a
        SubjectMatch, ResourceMatch, or ActionMatch
        @param function the Function that represents the MatchId
        @param eval the AttributeDesignator or AttributeSelector to be used to 
        select attributes from the request context
        @param attrValue the AttributeValue to compare against
        @raise TypeError if the input type isn't a valid value
        '''
        if _type not in self.__class__.types:
            raise TypeError("Type is [%d] but it must be one of %r" % 
                            (type, self.__class__.types))
        self.type = _type
        self.function = function
        self.eval = _eval
        self.attrValue = attributeValue

    def _getType(self):
        return self._type
    
    def _setType(self, type):
        if type not in self.__class__.types:
            raise TypeError('Type value "%d" not recognised, expecting one of '
                            '%r types' % (type, self.__class__.types))
        self._type = type
        
    type = property(fget=_getType, fset=_setType, 
                    doc="the type of match for this target")
    
    @classmethod
    def getInstance(cls, root, prefix):
        '''Creates a TargetMatch by parsing a node, using the
        input prefix to determine whether this is a SubjectMatch, 
        ResourceMatch, or ActionMatch.
     
        @param root the node to parse for the TargetMatch
        @param prefix a String indicating what type of TargetMatch
        to instantiate (Subject, Resource, or Action)
        @param xpathVersion the XPath version to use in any selectors, or
        null if this is unspecified (ie, not supplied in
        the defaults section of the policy)

        @return a new TargetMatch constructed by parsing
        '''

        type = ["Subject", "Resource", "Action"].index(prefix)
        if type not in cls.types:
            raise TypeError("Unknown TargetMatch type: %s" % prefix)

        # function type
        funcId = root.attrib["MatchId"]
        factory = FunctionFactory.getTargetInstance()
        try:
            function = factory.createFunction(funcId)
        except UnknownIdentifierException, e:
            raise ParsingException("Unknown MatchId: %s" % e)
        
        except FunctionTypeException, e:
            # try to create an abstract function
            try:
                function = factory.createAbstractFunction(funcId, root)
            except Exception, e:
                raise ParsingException("invalid abstract function: %s" % e)
            
        attributeFactory = AttributeFactory.getInstance()
        
        # Get the designator or selector being used, and the attribute
        # value paired with it
        for elem in root:
            localName = QName.getLocalPart(elem.tag)

            if localName == prefix + "AttributeDesignator":
                _eval = AttributeDesignator.getInstance(elem, type)
                
            elif localName == "AttributeSelector":
                _eval = AttributeSelector.getInstance(elem)
                
            elif localName == "AttributeValue":
                try:
                    attributeValue = attributeFactory.createValue(root=elem)
                except UnknownIdentifierException, e:
                    raise ParsingException("Unknown Attribute Type: %s" % e)

        # finally, check that the inputs are valid for this function
        inputs = [attributeValue, _eval]
        function.checkInputsNoBag(inputs)
        
        return cls(type, function, _eval, attributeValue)
    

    def match(self, context):
        '''determines whether this TargetMatch matches
        the input request (whether it is applicable)

        @param context the representation of the request

        @return the result of trying to match the TargetMatch and the request
        '''
        
        result = self.eval.evaluate(context)
        
        if result.indeterminate():
            # in this case, we don't ask the function for anything, and we
            # simply return INDETERMINATE
            return MatchResult(MatchResult.INDETERMINATE, result.getStatus())
        

        bag = result.getAttributeValue()

        if len(bag) > 0:
            
            # we got back a set of attributes, so we need to iterate through
            # them, seeing if at least one matches
            atLeastOneError = False
            firstIndeterminateStatus = None

            for i in bag:
                inputs = []

                inputs.append(attrValue)
                inputs.append(i)

                # do the evaluation
                match = evaluateMatch(inputs, context)
                
                # we only need one match for this whole thing to match
                if match.getResult() == MatchResult.MATCH:
                    return match

                # if it was INDETERMINATE, we want to remember for later
                if match.getResult() == MatchResult.INDETERMINATE:
                    atLeastOneError = True

                    # there are no rules about exactly what status data
                    # should be returned here, so like in the combining
                    # also, we'll just track the first error
                    if firstIndeterminateStatus == None:
                        firstIndeterminateStatus = match.getStatus()

            # if we got here, then nothing matched, so we'll either return
            # INDETERMINATE or NO_MATCH
            if atLeastOneError:
                return MatchResult(MatchResult.INDETERMINATE,
                                   firstIndeterminateStatus)
            else:
                return MatchResult(MatchResult.NO_MATCH)

        else:
            # this is just an optimization, since the loop above will
            # actually handle this case, but this is just a little
            # quicker way to handle an empty bag
            return MatchResult(MatchResult.NO_MATCH)
    
    def evaluateMatch(self, inputs, context):
        '''Private helper that evaluates an individual match'''
        
        # evaluate the function
        result = function.evaluate(inputs, context)

        # if it was indeterminate, then that's what we return immediately
        if result.indeterminate():
            return MatchResult(MatchResult.INDETERMINATE,
                               result.getStatus())

        # otherwise, we figure out if it was a match
        bool = result.getAttributeValue()

        if bool.getValue():
            return MatchResult(MatchResult.MATCH)
        else:
            return MatchResult(MatchResult.NO_MATCH)

    def encode(self, output, indenter=None):
        '''Encodes this TargetMatch into its XML representation 
        and writes this encoding to the given OutputStream with no
        indentation.
        @param output a stream into which the XML-encoded data is written'''
        raise NotImplementedError()
    
    
class Status(XacmlBase):
    STATUS_MISSING_ATTRIBUTE = \
          "urn:oasis:names:tc:xacml:1.0:status:missing-attribute"
    STATUS_OK = "urn:oasis:names:tc:xacml:1.0:status:ok"
    STATUS_PROCESSING_ERROR = \
          "urn:oasis:names:tc:xacml:1.0:status:processing-error"
    STATUS_SYNTAX_ERROR = \
          "urn:oasis:names:tc:xacml:1.0:status:syntax-error"       


class Effect(XacmlBase):
    def __str__(self):
        raise NotImplementedError()

             
class DenyEffect(Effect):
    def __str__(self):
        return 'deny'

          
class PermitEffect(Effect):
    def __str__(self):
        return 'permit'


class PolicyTreeElement(XacmlBase):
    pass


class Rule(PolicyTreeElement):
    '''Represents the RuleType XACML type. This has a target for matching, and
    encapsulates the condition and all sub-operations that make up the heart
    of most policies.
    '''
    def __init__(self, ruleId, effect, description, target, condition):
        '''Creates a new <code>Rule</code> object.
        
        @param ruleId: the rule's identifier
        @param effect: the effect to return if the rule applies (either
                      Permit or Deny) as specified in <code>Result</code>
        @param description: a textual description, or None
        @param target: the rule's target, or None if the target is to be
                      inherited from the encompassing policy
        @param condition: the rule's condition, or None if there is none
        '''
        
        self.idAttr = ruleId
        
        # Effect is the intended consequence of the satisfied rule. It can 
        # either take the value Permit or Deny.
        self.effect = effect
        
        self.description = description
        
        # Target, as in the case of a policy, helps in determining whether or 
        # not a rule is relevant for a request. The mechanism for achieving 
        # this is also similar to how it is done in the case of a target for a 
        # policy.
        self.target = target
        
        # Conditions are statements about attributes that upon evaluation 
        # return either True, False, or Indeterminate.
        self.condition = condition
        
    @classmethod
    def getInstance(cls, root):
        '''Returns a new instance of the Rule class based on an XML element.
        The element must be the root of an XML RuleType.
        
        @param root: the root of a RuleType XML type
        @raise ParsingException: if the RuleType is invalid
        '''
        _id = None
        name = None
        effect = 0
        description = None
        target = None
        condition = None

        _id = root.attrib.get("RuleId")
        if _id is None:
            raise ParsingException("Error parsing required attribute RuleId")
        
        str = root.attrib.get("Effect")
        if str == "Permit":
            effect = Result.DECISION_PERMIT
        elif str == "Deny":
            effect = Result.DECISION_DENY
        else:
            raise ParsingException("Invalid Effect: %s" % effect)
        

        # next, get the elements
        for elem in list(root):
            cname = QName.getLocalPart(elem.tag)

            if cname == "Description":
                description = elem.text
                
            elif cname == "Target":
                target = Target.getInstance(elem)
                
            elif cname == "Condition":
                condition = Apply.getConditionInstance(elem)
            
        return Rule(_id, effect, description, target, condition)
    
    def getEffect(self): 
        '''Returns the effect that this <code>Rule</code> will return from
        the evaluate method (Permit or Deny) if the request applies.
        
        @return a decision effect, as defined in <code>Result</code>
        '''
        return self.effect
    
    def getId(self):
        '''Returns the id of this <code>Rule</code>
        
        @return the rule id'''
        return self.idAttr
    
    def getDescription(self):
        '''Returns the given description of this <code>Rule</code> or None if 
        there is no description
        
        @return: the description or None'''
        return self.description
     
    def getTarget(self):
        '''Returns the target for this Rule or None if there is no target
        
        @return: the rule's target'''
        return self.target

    def getChildren(self):
        '''Since a rule is always a leaf in a policy tree because it can have
        no children, this always returns an empty list.
        
        @return: a list with no elements'''
        return []
    
    def getCondition(self):
        '''Returns the condition for this <code>Rule</code> or None if there
        is no condition
        
        @return: the rule's condition
        '''
        return self.condition
    
    def match(self, context):
        '''Given the input context sees whether or not the request matches this
        <code>Rule</code>'s <code>Target</code>. Note that unlike the matching
        done by the <code>evaluate</code> method, if the <code>Target</code>
        is missing than this will return Indeterminate. This lets you write
        your own custom matching routines for rules but lets evaluation
        proceed normally.
        
        @param context the representation of the request
        
        @return the result of trying to match this rule and the request
        '''
        if target is None: 
            code = []
            code.append(Status.STATUS_PROCESSING_ERROR)
            status = Status(code, "no target available for matching a rule")

            return MatchResult(MatchResult.INDETERMINATE, status)
        

        return target.match(context)
    
    def evaluate(self, context): 
        '''Evaluates the rule against the supplied context. This will check 
        that  the target matches, and then try to evaluate the condition. If 
        the target and condition apply, then the rule's effect is returned in
        the result.

        Note that rules are not required to have targets. If no target is
        specified, then the rule inherits its parent's target. In the event
        that this Rule has no Target then the match is assumed to be true, 
        since evaluating a policy tree to this level required the parent's 
        target to match.
        
        @param context: the representation of the request we're evaluating
        
        @return: the result of the evaluation
        '''
        # If the Target is None then it's supposed to inherit from the
        # parent policy, so we skip the matching step assuming we wouldn't
        # be here unless the parent matched
        if target is not None: 
            match = target.match(context)
            result = match.getResult()

            # if the target didn't match, then this Rule doesn't apply
            if result == MatchResult.NO_MATCH:
                return Result(Result.DECISION_NOT_APPLICABLE,
                              context.getResourceId().encode())

            # if the target was indeterminate, we can't go on
            if result == MatchResult.INDETERMINATE:
                return Result(Result.DECISION_INDETERMINATE,
                              match.getStatus(),
                              context.getResourceId().encode())
        

        # if there's no condition, then we just return the effect...
        if condition is None:
            return Result(effectAttr, context.getResourceId().encode())

        # ...otherwise we evaluate the condition
        result = condition.evaluate(context)
        
        if result.indeterminate():
            # if it was INDETERMINATE, then that's what we return
            return Result(Result.DECISION_INDETERMINATE,
                          result.getStatus(),
                          context.getResourceId().encode())
        else: 
            # otherwise we return the effect on true, and NA on false
            boolVal = result.getAttributeValue()

            if boolVal.getValue():
                return Result(effectAttr,
                              context.getResourceId().encode())
            else:
                return Result(Result.DECISION_NOT_APPLICABLE,
                              context.getResourceId().encode())
    
    def encode(self, output=None, indenter=None): 
        '''Encodes this Rule into its XML representation and writes
        this encoding to the given <code>OutputStream</code> with
        indentation.
        
        @param output: a stream into which the XML-encoded data is written
        @param indenter: an object that creates indentation strings'''
        raise NotImplementedError()

          
class Attribute(XacmlBase):
    def __init__(self, _id, type=None, issuer=None, issueInstant=None, 
                 value=None):
        self.id = _id
        self.type = type or value.__class__
        self.issuer = issuer
        self.issueInstant = issueInstant
        self.value = value

       
class Request(XacmlBase):
    '''XACML Request XacmlBase
    
    TODO: refactor from this initial placeholder'''
    def __init__(self, subject, resource, action=None, environment={}):
        self.subject = subject
        self.resource = resource
        self.action = action
        self.environment = environment

class Response(XacmlBase):
    pass


class PDP(XacmlBase):
    '''Modify PDPInterface to use the four XACML request designators: subject,
    resource, action and environment
    
    This is an initial iteration toward a complete XACML implementation'''
    def __init__(self, *arg, **kw):
          pass
    
    def evaluate(self, request):
          '''Make access control decision - override this in a derived class to
          implement the decision logic but this method may be called within
          the derived method to check input types
          
          @param request: request object containing the subject, resource,
          action and environment
          @type request: ndg.security.common.authz.xacml.Request
          @return reponse object
          @rtype: ndg.security.common.authz.xacml.Response
          '''
          raise NotImplementedError()


class RuleCombiningAlg(XacmlBase):
    id = None


class DenyOverrides(RuleCombiningAlg):
    '''Deny-overrides: If any rule evaluates to Deny, then the final 
    authorization decision is also Deny.'''
    id = 'Deny-overrides'
   
   
class OrderedDenyOverrides(RuleCombiningAlg):
    '''Ordered-deny-overrides: Same as deny-overrides, except the order in 
    which relevant rules are evaluated is the same as the order in which they 
    are added in the policy.'''
    id = 'Ordered-deny-overrides'
    
    
class PermitOverrides(RuleCombiningAlg):
    '''Permit-overrides: If any rule evaluates to Permit, then the final 
    authorization decision is also Permit.'''
    
    
class OrderedPermitOverrides(RuleCombiningAlg):
    '''Ordered-permit-overrides: Same as permit-overrides, except the order in
    which relevant rules are evaluated is the same as the order in which they 
    are added in the policy.'''
    id = 'Ordered-permit-overrides'
    
    
class FirstApplicable(RuleCombiningAlg):
    '''First-applicable: The result of the first relevant rule encountered is 
    the final authorization decision as well.'''
    id = 'First-applicable'


class EvaluationCtx(object):

    # The standard URI for listing a resource's id
    RESOURCE_ID = "urn:oasis:names:tc:xacml:1.0:resource:resource-id"

    # The standard URI for listing a resource's scope
    RESOURCE_SCOPE = "urn:oasis:names:tc:xacml:1.0:resource:scope"

    # Resource scope of Immediate (only the given resource)
    SCOPE_IMMEDIATE = 0

    # Resource scope of Children (the given resource and its direct
    # children)
    SCOPE_CHILDREN = 1

    # Resource scope of Descendants (the given resource and all descendants
    # at any depth or distance)
    SCOPE_DESCENDANTS = 2
    
    def getRequestRoot(self):
        '''Returns the DOM root of the original RequestType XML document, if
        this context is backed by an XACML Request. If this context is not
        backed by an XML representation, then an exception is thrown.'''
        raise NotImplementedError()

    def getResourceId(self):
        '''Returns the identifier for the resource being requested.'''
        raise NotImplementedError()

    def getScope(self):
        '''Returns the resource scope, which will be one of the three fields
        denoting Immediate, Children, or Descendants.'''
        raise NotImplementedError()

    def setResourceId(self, resourceId):
        '''Changes the value of the resource-id attribute in this context. This
        is useful when you have multiple resources (ie, a scope other than
        IMMEDIATE), and you need to keep changing only the resource-id to
        evaluate the different effective requests.'''
        raise NotImplementedError()

    def getCurrentTime(self):
        '''Returns the cached value for the current time. If the value has 
        never been set by a call to setCurrentTime, or if caching 
        is not enabled in this instance, then this will return null.'''
        raise NotImplementedError()

    def setCurrentTime(self, currentTime):
        '''Sets the current time for this evaluation. If caching is not enabled
        for this instance then the value is ignored.
     
        @param currentTime the dynamically resolved current time'''
        raise NotImplementedError()

    def getCurrentDate(self):
        '''Returns the cached value for the current date. If the value has 
        never been set by a call to setCurrentDate, or if caching 
        is not enabled in this instance, then this will return null.'''
        raise NotImplementedError()

    def setCurrentDate(self, currentDate):
        '''Sets the current date for this evaluation. If caching is not enabled
        for this instance then the value is ignored.'''
        raise NotImplementedError()

    def getCurrentDateTime(self):
        '''Returns the cached value for the current dateTime. If the value has
        never been set by a call to setCurrentDateTime, or if
        caching is not enabled in this instance, then this will return null.
        '''
        raise NotImplementedError()

    def setCurrentDateTime(self, currentDateTime):
        '''Sets the current dateTime for this evaluation. If caching is not 
        enabled for this instance then the value is ignored.
     
        @param currentDateTime the dynamically resolved current dateTime'''
        raise NotImplementedError()

    def getSubjectAttribute(self, type, id, issuer=None, category=None):
        '''Returns available subject attribute value(s).
     
        @param type the type of the attribute value(s) to find
        @param id the id of the attribute value(s) to find
        @param issuer the issuer of the attribute value(s) to find or null
        @param category the category the attribute value(s) must be in
     
        @return a result containing a bag either empty because no values were
        found or containing at least one value, or status associated with an
        Indeterminate result'''
        raise NotImplementedError()
    
    def getResourceAttribute(self, type, id, issuer):
        '''Returns available resource attribute value(s).
     
        @param type the type of the attribute value(s) to find
        @param id the id of the attribute value(s) to find
        @param issuer the issuer of the attribute value(s) to find or null
     
        @return a result containing a bag either empty because no values were
        found or containing at least one value, or status associated with an
        Indeterminate result'''
        raise NotImplementedError()

    def getActionAttribute(self, type, id, issuer):
        '''Returns available action attribute value(s).
     
        @param type the type of the attribute value(s) to find
        @param id the id of the attribute value(s) to find
        @param issuer the issuer of the attribute value(s) to find or null
     
        @return a result containing a bag either empty because no values were
        found or containing at least one value, or status associated with an
        Indeterminate result'''
        raise NotImplementedError()

    def getEnvironmentAttribute(self, type, id, issuer):
        '''Returns available environment attribute value(s).
     
        @param type the type of the attribute value(s) to find
        @param id the id of the attribute value(s) to find
        @param issuer the issuer of the attribute value(s) to find or null
     
        @return a result containing a bag either empty because no values were
        found or containing at least one value, or status associated with an
        Indeterminate result'''
        raise NotImplementedError()

    def getAttribute(self, contextPath, namespaceNode, type, xpathVersion):
        '''Returns the attribute value(s) retrieved using the given XPath
        expression.
     
        @param contextPath the XPath expression to search
        @param namespaceNode the DOM node defining namespace mappings to use,
                            or null if mappings come from the context root
        @param type the type of the attribute value(s) to find
        @param xpathVersion the version of XPath to use
     
        @return a result containing a bag either empty because no values were
        
        found or containing at least one value, or status associated with an
        Indeterminate result'''
        raise NotImplementedError()
