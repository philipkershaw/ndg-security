"""XACML cond module contains condition function classes

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
__date__ = "02/04/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
import logging
log = logging.getLogger(__name__)

from ndg.security.common.utils.etree import QName
from ndg.security.common.authz.xacml.exceptions import \
    UnknownIdentifierException, ParsingException
from ndg.security.common.authz.xacml.cond.eval import Evaluatable, \
    EvaluationResult
from ndg.security.common.authz.xacml.attr import AnyURIAttribute, \
    Base64BinaryAttribute, BooleanAttribute, DateAttribute, DateTimeAttribute,\
    DayTimeDurationAttribute, DoubleAttribute, HexBinaryAttribute, \
    IntegerAttribute, RFC822NameAttribute, StringAttribute, TimeAttribute, \
    X500NameAttribute, YearMonthDurationAttribute, AttributeFactory, \
    AttributeDesignator


class Apply(Evaluatable):
    '''Represents the XACML ApplyType and ConditionType XML types.'''

    def __init__(self, function, evals, bagFunction=None, isCondition=False):
        '''Constructs an Apply object. Throws an
        IllegalArgumentException if the given parameter list
        isn't valid for the given function.
        
        @param function the Function to use in evaluating the elements in the 
        apply
        @param evals the contents of the apply which will be the parameters
        to the function, each of which is an Evaluatable
        @param bagFunction the higher-order function to use
        @param isCondition Rrue if this Apply is a Condition, False otherwise
        '''
    
        # check that the given inputs work for the function
        inputs = evals
        if bagFunction is not None:
            inputs = [bagFunction]
            inputs += evals
        
        function.checkInputs(inputs)

        # if everything checks out, then store the inputs
        self._function = function
        self._evals = tuple(evals)
        self.bagFunction = bagFunction
        self.isCondition = isCondition
    
    
    @classmethod
    def getConditionInstance(cls, root):
        '''Returns an instance of an Apply based on the given DOM
        root node. This will actually return a special kind of
        Apply, namely an XML ConditionType, which is the root
        of the condition logic in a RuleType. A ConditionType is the same
        as an ApplyType except that it must use a FunctionId that returns
        a boolean value.
        
        @param root the DOM root of a ConditionType XML type
        '''
        from ndg.security.common.authz.xacml.cond.factory import \
            FunctionFactory
        cls.__getInstance(root, FunctionFactory.getConditionInstance(), True)
    
    
    @classmethod
    def getInstance(cls, root):
        '''Returns an instance of Apply based on the given root.
         
        @param root: the ElementTree.Element root of a ConditionType XML type
        @raise ParsingException: if this is not a valid ApplyType
        '''
        from ndg.security.common.authz.xacml.cond.factory import \
            FunctionFactory
        cls.__getInstance(root, FunctionFactory.getGeneralInstance(), True)
         
        
    @classmethod
    def __getInstance(cls, root, factory, isCondition):
        '''This is a helper method that is called by the two getInstance
        methods. It takes a factory so we know that we're getting the right
        kind of function.'''
     
        function = cls.__getFunction(root, factory)
        bagFunction = None
        evals = []
        
        attrFactory = AttributeFactory.getInstance()

        for elem in root: 
            name = QName.getLocalPart(elem.tag)

            if name == "Apply":
                evals.append(Apply.getInstance(elem))
               
            elif name == "AttributeValue":
                try: 
                    evals.append(attrFactory.createValue(elem))
                    
                except UnknownIdentifierException, e:
                    raise ParsingException("Unknown DataType: %s" % e)
                
            elif name == "SubjectAttributeDesignator":
                evals.append(AttributeDesignator.getInstance(elem,
                                      AttributeDesignator.SUBJECT_TARGET))
                
            elif name =="ResourceAttributeDesignator":
                evals.append(AttributeDesignator.getInstance(elem,
                                      AttributeDesignator.RESOURCE_TARGET))
                
            elif name == "ActionAttributeDesignator": 
                evals.append(AttributeDesignator.getInstance(elem,
                                      AttributeDesignator.ACTION_TARGET))
                
            elif name == "EnvironmentAttributeDesignator":
                evals.append(AttributeDesignator.getInstance(elem,
                                      AttributeDesignator.ENVIRONMENT_TARGET))
                
            elif name == "AttributeSelector":
                evals.append(AttributeSelector.getInstance(elem))
                
            elif name == "Function": 
                # while the schema doesn't enforce this, it's illegal to
                # have more than one FunctionType in a given ApplyType
                if bagFunction != None:
                    raise ParsingException("Too many FunctionTypes")

                from ndg.security.common.authz.xacml.cond.factory import \
                    FunctionFactory
                bagFunction = cls.__getFunction(elem, 
                                        FunctionFactory.getGeneralInstance())
            
        return Apply(function, evals, bagFunction, isCondition)


    @classmethod
    def __getFunction(cls, root, factory):
        '''Helper method that tries to get a function instance'''

        functionName = root.attrib["FunctionId"]
        try:
            # try to get an instance of the given function
            return factory.createFunction(functionName)
        
        except UnknownIdentifierException, e:
            raise ParsingException("Unknown FunctionId in Apply: %s" % e)
        
        except FunctionTypeException, e:
            # try creating as an abstract function, using a general factory
            try:
                from ndg.security.common.authz.xacml.cond.factory import \
                    FunctionFactory
                functionFactory = FunctionFactory.getGeneralInstance()
                return functionFactory.createAbstractFunction(functionName, 
                                                              root)
            except Exception, e:
                # any exception at this point is a failure
                raise ParsingException("failed to create abstract function %s "
                                       ": %s" % (functionName, e))  
            
    def getFunction(self):
        '''Returns the Function used by this Apply.
        
        @return the Function'''
        return self._function
    
    def getChildren(self):
        '''Returns the List of children for this Apply.
        The List contains Evaluatables. The list is
        unmodifiable, and may be empty.
        
        @return a List of Evaluatables'''
        return self._evals
    
    def getHigherOrderFunction(self):
        '''Returns the higher order bag function used by this Apply
        if it exists, or null if no higher order function is used.
        
        @return the higher order Function or null'''
        return self.bagFunction
    
    def isCondition(self):
        '''Returns whether or not this ApplyType is actually a ConditionType.
        
        @return whether or not this represents a ConditionType'''
        return isCondition

    def evaluate(self, context):
        '''Evaluates the apply object using the given function. This will in
        turn call evaluate on all the given parameters, some of which may be
        other Apply objects.
        
        @param context the representation of the request
        
        @return the result of trying to evaluate this apply object'''
        parameters = self.evals

        # see if there is a higher-order function in here
        if bagFunction != None:
            # this is a special case, so we setup the parameters, starting
            # with the function
            parameters = [bagFunction]

            # now we evaluate all the parameters, returning INDETERMINATE
            # if that's what any of them return, and otherwise tracking
            # all the AttributeValues that get returned
            for eval in self.evals:
                result = eval.evaluate(context)
                
                # in a higher-order case, if anything is INDETERMINATE, then
                # we stop right away
                if result.indeterminate():
                    return result

                parameters.add(result.getAttributeValue())
            
        # now we can call the base function
        return function.evaluate(parameters, context)
         
    def getType(self):
        '''Returns the type of attribute that this object will return on a call
        to evaluate. In practice, this will always be the same as
        the result of calling getReturnType on the function used
        by this object.
        
        @return the type returned by evaluate'''
        return self.function.getReturnType()
      
    def evaluatesToBag(self):
        '''Returns whether or not the Function will return a bag
        of values on evaluation.
        
        @return true if evaluation will return a bag of values, false otherwise
        '''
        return self.function.returnsBag()

    def encode(self, output, indenter):
        '''Encodes this Apply into its XML representation and
        writes this encoding to the given OutputStream with
        indentation.
        
        @param output a stream into which the XML-encoded data is written
        @param indenter an object that creates indentation strings'''
        raise NotImplementedError()
        
class Function(object):
    '''Interface that all functions in the system must implement.'''
 
    def evaluate(self, inputs, context):
        '''Evaluates the Function using the given inputs.
        The List contains Evaluatables which are all
        of the correct type if the Function has been created as
        part of an Apply or TargetMatch, but which
        may otherwise be invalid. Each parameter should be evaluated by the
        Function, unless this is a higher-order function (in
        which case the Apply has already evaluated the inputs
        to check for any INDETERMINATE conditions), or the Function
        doesn't need to evaluate all inputs to determine a result (as in the
        case of the or function). The order of the List is
        significant, so a Function should have a very good reason
        if it wants to evaluate the inputs in a different order.
        <p>
        Note that if this is a higher-order function, like any-of, then
        the first argument in the List will actually be a Function
        object representing the function to apply to some bag. In this case,
        the second and any subsequent entries in the list are
        AttributeValue objects (no INDETERMINATE values are
        allowed, so the function is not given the option of dealing with
        attributes that cannot be resolved). A function needs to know if it's
        a higher-order function, and therefore whether or not to look for
        this case. Also, a higher-order function is responsible for checking
        that the inputs that it will pass to the Function
        provided as the first parameter are valid, ie. it must do a
        checkInputs on its sub-function when
        checkInputs is called on the higher-order function.
        
        @param inputs the List of inputs for the function
        @param context the representation of the request
        
        @return a result containing the AttributeValue computed
                when evaluating the function, or Status
                specifying some error condition'''
        raise NotImplementedError()


    def getIdentifier(self):
        '''Returns the identifier of this function as known by the factories.
        In the case of the standard XACML functions, this will be one of the
        URIs defined in the standard namespace. This function must always
        return the complete namespace and identifier of this function.
        
        @return the function's identifier'''
        raise NotImplementedError()

    def getReturnType(self):
        '''Provides the type of AttributeValue that this function
        returns from evaluate in a successful evaluation.
        
        @return the type returned by this function
        '''
        raise NotImplementedError()
 
    def returnsBag(self):
        '''Tells whether this function will return a bag of values or just a
        single value.
        
        @return true if evaluation will return a bag, false otherwise'''
        raise NotImplementedError()

    def checkInputs(self, inputs):
        '''Checks that the given inputs are of the right types, in the right
        order, and are the right number for this function to evaluate. If
        the function cannot accept the inputs for evaluation, an
        IllegalArgumentException is thrown.
        
        @param inputs a list of Evaluatables, with the first argument being a 
        Function if this is a higher-order function
        
        @throws TypeError if the inputs do match what the function accepts for
        evaluation
        '''
        raise NotImplementedError()

    def checkInputsNoBag(self, inputs):
        '''Checks that the given inputs are of the right types, in the right
        order, and are the right number for this function to evaluate. If
        the function cannot accept the inputs for evaluation, an
        IllegalArgumentException is thrown. Unlike the other
        checkInput method in this interface, this assumes that
        the parameters will never provide bags of values. This is useful if
        you're considering a target function which has a designator or
        selector in its input list, but which passes the values from the
        derived bags one at a time to the function, so the function doesn't
        have to deal with the bags that the selector or designator
        generates.
        
        @param inputs a list of Evaluatables, with the first argument being a 
        Function if this is a higher-order function
        
        @throws TypeError if the inputs do match what the function accepts for
        evaluation'''
        raise NotImplementedError()


class FunctionBase(Function):
    FUNCTION_NS = "urn:oasis:names:tc:xacml:1.0:function:"
    supportedIdentifiers = ()
    
    def __init__(self, 
                 functionName, 
                 functionId=None, 
                 paramType=None,
                 paramIsBag=False,
                 numParams=-1, 
                 minParams=0,
                 returnType='', 
                 returnsBag=False):
        '''
        @param functionName: the name of this function as used by the factory
                            and any XACML policies
        @param functionId: an optional identifier that can be used by your
                          code for convenience
        @param paramType: the type of each parameter, in order, required by
                          this function, as used by the factory and any XACML
                           documents
        @param paramIsBag: whether or not each parameter is actually a bag
                          of values
        @param numParams: the number of parameters required by this function,
        or -1 if any number are allowed
        @param minParams: the minimum number of parameters required if 
        numParams is -1 
        @param returnType: the type returned by this function, as used by
                          the factory and any XACML documents
        @param returnsBag: whether or not this function returns a bag of values
        '''          
        self.functionName = functionName
        self.functionId = functionId
        self.returnType = returnType
        self.returnsBag = returnsBag
    
        self.paramType = paramType
                
        if isinstance(self.paramType, (list, tuple)):
            if not self.paramType:
                raise TypeError('"paramType" is set to an empty list or tuple')
            self.singleType = False
            
            # Keep this test within the paramType is-a-list if-block otherwise
            # it may fail checking the length of a bool
            if len(paramIsBag) != len(self.paramType):
                raise TypeError('"paramIsBag" and "paramType" inputs must '
                                'have the same length')
        else:
            self.singleType = True
            
            # These only apply if the input parameters are all of a single type
            self.numParams = numParams
            self.minParams = minParams
            
        self.paramIsBag = paramIsBag
        
  
    def _setFunctionName(self, functionName):
          if functionName not in self.__class__.supportedIdentifiers:
              functionList = ', '.join(self.__class__.supportedIdentifiers)
              raise TypeError("Function name [%s] is not on of the recognised "
                              "types: %s" % (functionName, functionList))
          self._functionName = functionName
          
    def _getFunctionName(self):
          return getattr(self, '_functionName', None)
    
    functionName = property(fset=_setFunctionName,
                                    fget=_getFunctionName)
          
    def checkInputs(self, inputs):
        '''Checks that the given inputs are of the right types, in the right 
        order, and are the right number for this function to evaluate.'''
        raise NotImplementedError()
            
    def checkInputsNoBag(self, inputs):
        '''Default handling of input checking. This does some simple checking
        based on the type of constructor used. If you need anything more
        complex, or if you used the simple constructor, then you must
        override this method.
    
        @param inputs: a list of Evaluatable instances
        
        @raise TypeError: if the inputs won't work
        '''
        numInputs = len(inputs)
        
        if self.singleType:
            # first check to see if we need bags
            if sum(self.paramIsBag):
                raise TypeError('"%s" needs bags on input' % self.functionName)

            # now check on the length
            if self.numParams != -1: 
                if numInputs != self.numParams:
                    raise TypeError('wrong number of args to "%s"' % 
                                    self.functionName)
            else: 
                if numInputs < self.minParams:
                    raise TypeError("not enough args to " % self.functionName)
            

            # finally check param list
            for eval in inputs: 
                if eval.getType().toString() != self.paramType:
                    raise TypeError("Illegal parameter: input type is %s but "
                                    "%s type is %s" % 
                                    (eval.getType().toString(),
                                     self.__class__.__name__,
                                     self.paramType))
            
        else: 
            # first, check the length of the inputs
            if len(self.paramType) != numInputs:
                raise TypeError('Wrong number of args to "%s"' % 
                                self.functionName)

            # Ensure everything is of the same, correct type
            it = zip(inputs, self.paramType, self.paramIsBag)
            for eval, paramType, paramIsBag in it:
                if eval.type != paramType or paramIsBag:
                    raise TypeError("Illegal parameter: input type is %s but "
                                    "%s type is %s" % 
                                    (eval.type,
                                     self.__class__.__name__,
                                     paramType))

 
    def evaluate(self, inputs, context):
        '''Evaluates the Function using the given inputs.'''
        raise NotImplementedError()
     
    def evalArgs(self, params, context, args):
        '''Evaluates each of the parameters, in order, filling in the argument
        array with the resulting values. If any error occurs, this method
        returns the error, otherwise null is returned, signalling that
        evaluation was successful for all inputs, and the resulting argument
        list can be used.
        
        @param params a list of Evaluatable objects representing the parameters
        to evaluate
        @param context the representation of the request
        @param args an array as long as the params list that will, on return, 
        contain the AttributeValues generated from evaluating all parameters

        @return None if no errors were encountered, otherwise
        an EvaluationResult representing the error
        '''
        index = 0

        for eval in params:
            # get and evaluate the next parameter
            result = eval.evaluate(context)

            # If there was an error, pass it back...
            if result.indeterminate():
                return result

            # ...otherwise save it and keep going
            args[index] = result.getAttributeValue()
            index += 1
            
        return None

# TODO: Condition classes - minimal implementation until opportunity to fully 
# implement   
class BagFunction(FunctionBase):
    def __init__(self, *arg, **kw):
        raise NotImplementedError()

class SetFunction(FunctionBase):
    '''Represents all of the Set functions, though the actual implementations
    are in two sub-classes specific to the condition and general set
    functions.'''

    # Base name for the type-intersection functions. To get the standard
    # identifier for a given type, use FunctionBase.FUNCTION_NS
    # + the datatype's base name (e.g., string) +
    # NAME_BASE_INTERSECTION.
    NAME_BASE_INTERSECTION = "-intersection"

    # Base name for the type-at-least-one-member-of functions. To get the
    # standard identifier for a given type, use
    # FunctionBase.FUNCTION_NS + the datatype's base name (e.g., string) +
    # NAME_BASE_AT_LEAST_ONE_MEMBER_OF.
    NAME_BASE_AT_LEAST_ONE_MEMBER_OF = "-at-least-one-member-of"

    # Base name for the type-union funtions. To get the standard
    # identifier for a given type, use FunctionBase.FUNCTION_NS
    # + the datatype's base name (e.g., string) + NAME_BASE_UNION.
    NAME_BASE_UNION = "-union"

    # Base name for the type-subset funtions. To get the standard
    # identifier for a given type, use FunctionBase.FUNCTION_NS
    # + the datatype's base name (e.g., string) + NAME_BASE_SUBSET.
    NAME_BASE_SUBSET = "-subset"

    # Base name for the type-set-equals funtions. To get the standard
    # identifier for a given type, use FunctionBase.FUNCTION_NS
    # + the datatype's base name (e.g., string) + NAME_BASE_SET_EQUALS.
    NAME_BASE_SET_EQUALS = "-set-equals"

    
    # A complete list of all the XACML datatypes supported by the Set
    # functions
    baseTypes = (
        StringAttribute.identifier,
        BooleanAttribute.identifier,
        IntegerAttribute.identifier,
        DoubleAttribute.identifier,
        DateAttribute.identifier,
        DateTimeAttribute.identifier,
        TimeAttribute.identifier,
        AnyURIAttribute.identifier,
        HexBinaryAttribute.identifier,
        Base64BinaryAttribute.identifier,
        DayTimeDurationAttribute.identifier,
        YearMonthDurationAttribute.identifier,
        X500NameAttribute.identifier,
        RFC822NameAttribute.identifier)
    
    # A complete list of all the XACML datatypes supported by the Set
    # functions, using the "simple" form of the names (eg, string
    # instead of http:#www.w3.org/2001/XMLSchema#string)
    simpleTypes = (
        "string", 
        "boolean", 
        "integer", 
        "double", 
        "date", 
        "dateTime",
        "time", 
        "anyURI", 
        "hexBinary", 
        "base64Binary", 
        "dayTimeDuration",
        "yearMonthDuration", 
        "x500Name", 
        "rfc822Name")

    # Define as lambda to avoid reference to classes that aren't defined yet
    _getSupportedIdentifiers = lambda: \
        ConditionSetFunction.supportedIdentifiers +\
        GeneralSetFunction.supportedIdentifiers
        
    # All the function identifiers supported by this class.
    supportedIdentifiers = property(fget=_getSupportedIdentifiers)

    
    def __init__(self, 
                 functionName, 
                 functionId, 
                 argumentType, 
                 returnType,
                 returnsBag):
        '''Constuctor used by the general and condition subclasses only.
        If you need to create a new SetFunction instance you
        should either use one of the getInstance methods or
        construct one of the sub-classes directly.
        
        @param functionName the identitifer for the function
        @param functionId an optional, internal numeric identifier
        @param argumentType the datatype this function accepts
        @param returnType the datatype this function returns
        @param returnsBag whether this function returns bags
        '''
        super(SetFunction, self).__init__(functionName, 
                                          functionId, 
                                          argumentType, 
                                          True, 
                                          2, 
                                          returnType,
                                          returnsBag)
    
        
    @classmethod
    def getIntersectionInstance(cls, functionName, argumentType):
        '''Creates a new instance of the intersection set function.
        This should be used to create support for any new attribute types
        and then the new SetFunction object should be added
        to the factory (all set functions for the base types are already
        installed in the factory).
        
        @param functionName the name of the function
        @param argumentType the attribute type this function will work with
        
        @return a new SetFunction for the given type
        '''
        return GeneralSetFunction(functionName, argumentType,
                                  cls.NAME_BASE_INTERSECTION)
    
    @classmethod
    def getAtLeastOneInstance(cls, functionName, argumentType):
        '''Creates a new instance of the at-least-one-member-of set function.
        This should be used to create support for any new attribute types
        and then the new SetFunction object should be added
        to the factory (all set functions for the base types are already
        installed in the factory).
        
        @param functionName the name of the function
        @param argumentType the attribute type this function will work with
        
        @return a new SetFunction for the given type
        '''
        return ConditionSetFunction(functionName, argumentType,
                                    cls.NAME_BASE_AT_LEAST_ONE_MEMBER_OF)
    
    @classmethod
    def getUnionInstance(cls, functionName, argumentType):
        '''Creates a new instance of the union set function.
        This should be used to create support for any new attribute types
        and then the new SetFunction object should be added
        to the factory (all set functions for the base types are already
        installed in the factory).
        
        @param functionName the name of the function
        @param argumentType the attribute type this function will work with
        
        @return a new SetFunction for the given type
        '''
        return GeneralSetFunction(functionName, argumentType,
                                  cls.NAME_BASE_UNION)
    
    def getSubsetInstance(cls, functionName, argumentType):
        '''Creates a new instance of the subset set function.
        This should be used to create support for any new attribute types
        and then the new SetFunction object should be added
        to the factory (all set functions for the base types are already
        installed in the factory).
        
        @param functionName the name of the function
        @param argumentType the attribute type this function will work with
        
        @return a new SetFunction for the given type
        '''
        return ConditionSetFunction(functionName, argumentType,
                                    cls.NAME_BASE_SUBSET)
    
    def getSetEqualsInstance(cls, functionName, argumentType):
        '''Creates a new instance of the equals set function.
        This should be used to create support for any new attribute types
        and then the new SetFunction object should be added
        to the factory (all set functions for the base types are already
        installed in the factory).
        
        @param functionName the name of the function
        @param argumentType the attribute type this function will work with
        
        @return a new SetFunction for the given type
        '''
        return ConditionSetFunction(functionName, argumentType,
                                    cls.NAME_BASE_SET_EQUALS)

        
class ConditionSetFunction(SetFunction):
    '''Specific SetFunction class that supports all of the
    condition set functions: type-at-least-one-member-of, type-subset, and
    type-set-equals.'''
    
    # Private identifiers for the supported functions
    (ID_BASE_AT_LEAST_ONE_MEMBER_OF,
     ID_BASE_SUBSET,
     ID_BASE_SET_EQUALS) = range(3)

    # Mapping of function name to its associated id and parameter type
    idMap = {}
    typeMap = {}
    for baseType, simpleType in zip(SetFunction.baseTypes, 
                                    SetFunction.simpleTypes):
        baseName = SetFunction.FUNCTION_NS + simpleType

        idMap[baseName + SetFunction.NAME_BASE_AT_LEAST_ONE_MEMBER_OF] = \
                  ID_BASE_AT_LEAST_ONE_MEMBER_OF
        idMap[baseName + SetFunction.NAME_BASE_SUBSET] = ID_BASE_SUBSET
        idMap[baseName + SetFunction.NAME_BASE_SET_EQUALS] = ID_BASE_SET_EQUALS

        typeMap[baseName+SetFunction.NAME_BASE_AT_LEAST_ONE_MEMBER_OF]=baseType
        typeMap[baseName + SetFunction.NAME_BASE_SUBSET] = baseType
        typeMap[baseName + SetFunction.NAME_BASE_SET_EQUALS] = baseType
        
    del baseName
    
    # the actual supported ids
    supportedIdentifiers = tuple(idMap.keys())

    idMap.update({
        SetFunction.NAME_BASE_AT_LEAST_ONE_MEMBER_OF:
                                            ID_BASE_AT_LEAST_ONE_MEMBER_OF,
        SetFunction.NAME_BASE_SUBSET: ID_BASE_SUBSET,
        SetFunction.NAME_BASE_SET_EQUALS: ID_BASE_SET_EQUALS}
    )
    
    
    def __init__(self, functionName, dataType=None):
        '''Constructor that is used to create one of the condition standard
        set functions. The name supplied must be one of the standard XACML
        functions supported by this class, including the full namespace,
        otherwise an exception is thrown. Look in SetFunction
        for details about the supported names.
        
        @param functionName the name of the function to create
        
        @throws IllegalArgumentException if the function is unknown
        '''
        if dataType is None:
            dataType = ConditionSetFunction.typeMap[functionName]
            
        super(ConditionSetFunction, self).__init__(functionName, 
                                ConditionSetFunction.idMap[functionName], 
                                dataType,
                                BooleanAttribute.identifier, 
                                False)

    
    def evaluate(self, inputs, context):
        '''Evaluates the function, using the specified parameters.
        
        @param inputs a list of Evaluatable objects representing the arguments 
        passed to the function
        @param context an EvaluationCtx so that the Evaluatable objects can be 
        evaluated
        @return an EvaluationResult representing the function's result
        '''

        # Evaluate the arguments
        argValues = AttributeValue[len(inputs)]
        evalResult = self.evalArgs(inputs, context, argValues)
        if evalResult is not None:
            return evalResult

        # Setup the two bags we'll be using
        bags = argValues[:1]

        result = None
        
        if self.functionId == \
            ConditionSetFunction.ID_BASE_AT_LEAST_ONE_MEMBER_OF:
            
            #-at-least-one-member-of takes two bags of the same type and
            # returns a boolean
    
            # true if at least one element in the first argument is in the
            # second argument (using the-is-in semantics)

            result = BooleanAttribute.getFalseInstance()
            for it in bags[0]: 
                if it in bags[1]: 
                    result = BooleanAttribute.getTrueInstance()
                    break
                
        elif self.functionId == ConditionSetFunction.ID_BASE_SUBSET:
            #-set-equals takes two bags of the same type and returns
            # a boolean
            
            # returns true if the first argument is a subset of the second
            # argument (ie, all the elements in the first bag appear in
            # the second bag) ... ignore all duplicate values in both
            # input bags

            subset = bags[1].containsAll(bags[0])
            result = BooleanAttribute.getInstance(subset)

        elif self.functionId == ConditionSetFunction.ID_BASE_SET_EQUALS:
            #-set-equals takes two bags of the same type and returns
            # a boolean

            # returns true if the two inputs contain the same elements
            # discounting any duplicates in either input ... this is the same
            # as applying the and function on the subset function with
            # the two inputs, and then the two inputs reversed (ie, are the
            # two inputs subsets of each other)

            equals = bags[1].containsAll(bags[0] and \
                              bags[0].containsAll(bags[1]))
            result = BooleanAttribute.getInstance(equals)
        
        return EvaluationResult(result) 
    
       
class GeneralSetFunction(SetFunction):
    supportedIdentifiers = ()
    def __init__(self, *arg, **kw):
        raise NotImplementedError()

class ConditionBagFunction(BagFunction):
    def __init__(self, *arg, **kw):
        raise NotImplementedError()
        
class HigherOrderFunction(Function):
    supportedIdentifiers = ()
    def __init__(self, *arg, **kw):
        raise NotImplementedError()

# TODO: Function classes - minimal implementation until opportunity to fully 
# implement                                    
class LogicalFunction(FunctionBase):

    def __init__(self, *arg, **kw):
        raise NotImplementedError()

class NOfFunction(FunctionBase):
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()
        
class NotFunction(FunctionBase):
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()
        
class ComparisonFunction(FunctionBase):
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()

class MatchFunction(FunctionBase):
    NAME_REGEXP_STRING_MATCH = FunctionBase.FUNCTION_NS + "regexp-string-match"
    NAME_RFC822NAME_MATCH = FunctionBase.FUNCTION_NS + "rfc822Name-match"
    NAME_X500NAME_MATCH = FunctionBase.FUNCTION_NS + "x500Name-match"     
    
    supportedIdentifiers = (
        NAME_REGEXP_STRING_MATCH, 
        NAME_RFC822NAME_MATCH,
        NAME_X500NAME_MATCH)
    
    functionIds = range(3)
    ID_REGEXP_STRING_MATCH, ID_X500NAME_MATCH, ID_RFC822NAME_MATCH=functionIds
    getId = dict(zip(supportedIdentifiers, functionIds))
    argParams = (
        (StringAttribute.identifier,)*2,
        (X500NameAttribute.identifier,)*2,
        (StringAttribute.identifier,
         RFC822NameAttribute.identifier)
    )
    getArgumentTypes = dict(zip(supportedIdentifiers, argParams))
    
    bagParams = (False, False)
    
    lut = {
          NAME_REGEXP_STRING_MATCH: 'regexpStringMatch',
          NAME_RFC822NAME_MATCH:    'rfc822NameMatch',
          NAME_X500NAME_MATCH:      'x500NameMatch'
    }
    
    def __init__(self, functionName, **kw):
          super(MatchFunction, self).__init__(functionName, 
                     functionId=MatchFunction.getId[functionName], 
                     paramType=MatchFunction.getArgumentTypes[functionName],
                     paramIsBag=MatchFunction.bagParams,
                     returnType=BooleanAttribute.identifier, 
                     returnsBag=False)


    def regexpStringMatch(self, regex, val):
          return re.match(regex, val) is not None
    
    def rfc822NameMatch(self, *inputs):
        raise NotImplementedError()
    
    def x500NameMatch(self, *inputs):
        raise NotImplementedError()
    
    def evaluate(self, inputs, context):
          matchFunction = getattr(self, MatchFunction.lut[self.functionName])
          match = matchFunction(self, *inputs)
          if match:
                return EvaluationResult(status=Status.STATUS_OK)


class EqualFunction(FunctionBase):
    supportedIdentifiers = (
          FunctionBase.FUNCTION_NS + "anyURI-equal",
          FunctionBase.FUNCTION_NS + "base64Binary-equal",
          FunctionBase.FUNCTION_NS + "boolean-equal",
          FunctionBase.FUNCTION_NS + "date-equal",
          FunctionBase.FUNCTION_NS + "dateTime-equal",
          FunctionBase.FUNCTION_NS + "dayTimeDuration-equal",
          FunctionBase.FUNCTION_NS + "double-equal",
          FunctionBase.FUNCTION_NS + "hexBinary-equal",
          FunctionBase.FUNCTION_NS + "integer-equal",
          FunctionBase.FUNCTION_NS + "rfc822Name-equal",
          FunctionBase.FUNCTION_NS + "string-equal",
          FunctionBase.FUNCTION_NS + "time-equal",
          FunctionBase.FUNCTION_NS + "x500Name-equal",
          FunctionBase.FUNCTION_NS + "yearMonthDuration-equal"
    )

    (NAME_ANYURI_EQUAL,
    NAME_BASE64BINARY_EQUAL,
    NAME_BOOLEAN_EQUAL,
    NAME_DATE_EQUAL,
    NAME_DATETIME_EQUAL,
    NAME_DAYTIME_DURATION_EQUAL,
    NAME_DOUBLE_EQUAL,
    NAME_HEXBINARY_EQUAL,
    NAME_INTEGER_EQUAL,
    NAME_RFC822NAME_EQUAL,
    NAME_STRING_EQUAL,
    NAME_TIME_EQUAL,
    NAME_X500NAME_EQUAL,
    NAME_YEARMONTH_DURATION_EQUAL) = supportedIdentifiers

    lut = {
          NAME_STRING_EQUAL: 'stringEqual'
    }
    
    _attrClasses = (
        AnyURIAttribute,
        Base64BinaryAttribute,
        BooleanAttribute,
        DateAttribute,
        DateTimeAttribute,
        DayTimeDurationAttribute,
        DoubleAttribute,
        HexBinaryAttribute,
        IntegerAttribute,
        RFC822NameAttribute,
        StringAttribute,
        TimeAttribute,
        X500NameAttribute,
        YearMonthDurationAttribute
    )
    
    typeMap = dict([(i, j.identifier) for i,j in zip(supportedIdentifiers,
                                                     _attrClasses)])
    
    def __init__(self, functionName, argumentType=None, **kw):
        if kw.get('functionId') is None:
            kw['functionId'] = functionName
            
        if kw.get('paramType') is None:
            kw['paramType'] = EqualFunction._getArgumentType(functionName)
            
        super(EqualFunction, self).__init__(functionName, **kw)

    def evaluate(self, inputs, evaluationCtx):
        function = EqualFunction.lut.get(self.functionName)
        if function is None:
            if self.functionName in supportedIdentifiers:
                raise NotImplementedError("No implementation is available for "
                                          "%s" % self.functionName)            
            else:
                raise AttributeError('function name "%s" not recognised '
                                     'for %s' % (self.functionName,
                                                 self.__class__.__name__))
                                  
        return getattr(self, function)(inputs, evaluationCtx)
    
    def stringEqual(self, inputs, evaluationCtx):
        result = self.evalArgs(inputs, context, argValues)
        if result is not None:
            return result
          
        return EvaluationResult(argValues[0] == argValues[1])
    
    @classmethod
    def _getArgumentType(cls, functionName):
        argumentType = cls.typeMap.get(functionName)
        if argumentType is None:
            if functionName in cls.supportedIdentifiers:
                raise NotImplementedError('No implementation is currently '
                                          'available for "%s"' % functionName)
            else:
                raise TypeError("Not a standard function: %s" % functionName)
          
        return argumentType

class AddFunction(FunctionBase):
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()
            
class SubtractFunction(FunctionBase):
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()
            
class MultiplyFunction(FunctionBase):
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()
            
class DivideFunction(FunctionBase):
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()
            
class ModFunction(FunctionBase):
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()

class AbsFunction(FunctionBase):
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()

class RoundFunction(FunctionBase):
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()

class FloorFunction(FunctionBase):
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()

class DateMathFunction(FunctionBase):
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()

class GeneralBagFunction(BagFunction):
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()

class NumericConvertFunction(FunctionBase):
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()

class StringNormalizeFunction(FunctionBase):
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()
    
class MapFunction(Function):        
    supportedIdentifiers = ()
    NAME_MAP = FunctionBase.FUNCTION_NS + "map"
    
    def __init__(self, *arg, **kw):
        raise NotImplementedError()

    @classmethod
    def getInstance(cls, root):
        raise NotImplementedError()
    
class FunctionProxy():

    def getInstance(self, root):
        raise NotImplementedError()

class MapFunctionProxy(FunctionProxy):

    def getInstance(self, root):
        return MapFunction.getInstance(root)
