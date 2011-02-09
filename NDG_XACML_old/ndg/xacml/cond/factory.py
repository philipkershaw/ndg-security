"""XACML function factory module

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
import logging
log = logging.getLogger(__name__)

from ndg.security.common.utils import UniqList
from ndg.xacml.cond import Function, EqualFunction, \
    LogicalFunction, NOfFunction, NotFunction, ComparisonFunction, \
    MatchFunction, ConditionBagFunction, ConditionSetFunction, \
    HigherOrderFunction, AddFunction, SubtractFunction, MultiplyFunction, \
    DivideFunction, ModFunction, AbsFunction, RoundFunction, FloorFunction, \
    DateMathFunction, GeneralBagFunction, NumericConvertFunction, \
    StringNormalizeFunction, GeneralSetFunction, MapFunction, \
    MapFunctionProxy, FunctionProxy

from ndg.xacml.exceptions import ParsingException, \
    UnknownIdentifierException, FunctionTypeException
      

class FunctionFactoryProxy(object):
    '''A simple proxy interface used to install new FunctionFactory's.
    The three kinds of factory (Target, Condition, and General) are tied
    together in this interface because implementors writing new factories
    should always implement all three types and provide them together'''
    
    @classmethod
    def getTargetFactory(cls):
        """Return a Target instance
        @type cls: FunctionFactoryProxy
        @param cls: class instance
        """
        raise NotImplementedError()

    @classmethod
    def getConditionFactory(cls):
        """Return a Condition instance
        @type cls: FunctionFactoryProxy
        @param cls: class instance
        """
        raise NotImplementedError()

    @classmethod
    def getGeneralFactory(cls):
        """General Factory method
        @type cls: FunctionFactoryProxy
        @param cls: class instance
        """
        raise NotImplementedError()


class FunctionFactory(object):
    '''Factory used to create all functions. There are three kinds of factories:
    general, condition, and target. These provide functions that can be used
    anywhere, only in a condition's root and only in a target (respectively).
    
    Note that all functions, except for abstract functions, are singletons, so
    any instance that is added to a factory will be the same one returned
    from the create methods. This is done because most functions don't have
    state, so there is no need to have more than one, or to spend the time
    creating multiple instances that all do the same thing.'''

    class defaultFactoryProxy(FunctionFactoryProxy):
        @classmethod
        def getTargetFactory(cls):
            return StandardFunctionFactory.getTargetFactory()
    
        @classmethod
        def getConditionFactory(cls):
            return StandardFunctionFactory.getConditionFactory()
    
        @classmethod
        def getGeneralFactory(cls):
            return StandardFunctionFactory.getGeneralFactory()                 
            
    @classmethod
    def getTargetInstance(cls):
        '''Returns the default FunctionFactory that will only provide those
        functions that are usable in Target matching.
        
        @return a FunctionFactory for target functions'''
        return cls.defaultFactoryProxy.getTargetFactory()
       
    @classmethod 
    def getConditionInstance(cls): 
        '''Returns the default FunctionFactory that provides access to all the
        functions. These Functions are a superset of the Condition functions.
        
        @return a FunctionFactory for all functions
        '''
        return cls.defaultFactoryProxy.getConditionFactory()
    
    @classmethod
    def getGeneralInstance(cls): 
        '''Sets the default factory. Note that this is just a place holder for
        now, and will be replaced with a more useful mechanism soon.'''
        return cls.defaultFactoryProxy.getGeneralFactory()
    
    
    def addFunction(self, function):
        '''Adds the function to the factory. Most functions have no state, so
        the singleton model used here is typically desirable. The factory will
        not enforce the requirement that a Target or Condition matching 
        function must be boolean.
        
        @param function the Function to add to the factory
        '''
        raise NotImplementedError()
        
    def addAbstractFunction(self, functionProxy, identity):
        '''Adds the abstract function proxy to the factory. This is used for
        those functions which have state, or change behaviour (for instance
        the standard map function, which changes its return type based on
        how it is used). 
        
        @param proxy the FunctionProxy to add to the factory
        @param identity the function's identifier
        '''
        raise NotImplementedError()        
    
    def getSupportedFunctions(self):
        '''Returns the function identifiers supported by this factory.
        
        @return a Set of Strings'''
        raise NotImplementedError()

    def createFunction(self, identity):
        '''Tries to get an instance of the specified function.
        
        @param identity the name of the function
        '''       
        raise NotImplementedError()
    
    def createAbstractFunction(self, identity, root):
        '''Tries to get an instance of the specified abstract function.
        
        @param identity the name of the function
        @param root the DOM root containing info used to create the function
        '''
        raise NotImplementedError()


class BasicFunctionFactoryProxy(FunctionFactoryProxy):
    '''A simple utility class that manages triples of function factories.'''
    
    # the triple of factories
    targetFactory = None
    conditionFactory = None
    generalFactory = None

    def __init__(self, targetFactory, conditionFactory, generalFactory): 
        '''Creates a new proxy.
        
        @param targetFactory the target factory provided by this proxy
        @param conditionFactory the target condition provided by this proxy
        @param generalFactory the general factory provided by this proxy
        '''
        BasicFunctionFactoryProxy.targetFactory = targetFactory
        BasicFunctionFactoryProxy.conditionFactory = conditionFactory
        BasicFunctionFactoryProxy.generalFactory = generalFactory
    
    @classmethod
    def getTargetFactory(cls):
        return cls.targetFactory

    @classmethod
    def getConditionFactory(cls):
        return cls.conditionFactory
    
    @classmethod
    def getGeneralFactory(cls):
        return cls.generalFactory
    

class BaseFunctionFactory(FunctionFactory):
    '''This is a basic implementation of <code>FunctionFactory</code>. It
    implements the insertion and retrieval methods, but it doesn't actually
    setup the factory with any functions. It also assumes a certain model
    with regard to the different kinds of functions (Target, Condition, and
    General). For this reason, you may want to re-use this class, or you 
    may want to extend FunctionFactory directly, if you're writing a new
    factory implementation.
    
    Note that while this class is thread-safe on all creation methods, it
    is not safe to add support for a new function while creating an instance
    of a function. This follows from the assumption that most people will
    initialize these factories up-front, and then start processing without
    ever modifying the factories. If you need these mutual operations to
    be thread-safe, then you should write a wrapper class that implements
    the right synchronization.
    '''
    
    def __init__(self, 
                 superset=None, 
                 supportedFunctions=[],
                 supportedAbstractFunctions={}):
        '''Sets a "superset factory". This is useful since
        the different function factories (Target, Condition, and General)
        have a superset relationship (Condition functions are a superset
        of Target functions, etc.). Adding a function to this factory will
        automatically add the same function to the superset factory.

        Constructor that defines the initial functions supported by this
        factory but doesn't use a superset factory.

        Constructor that defines the initial functions supported by this
        factory but doesn't use a superset factory.

        Constructor that defines the initial functions supported by this
        factory and uses a superset factory. Note that the functions
        supplied here are not propagated up to the superset factory, so
        you must either make sure the superset factory is correctly
        initialized or use BaseFunctionFactory(FunctionFactory)
        and then manually add each function.
       
        @param supportedFunctions a Set of Functions
        @param supportedAbstractFunctions a mapping from URI to
                                          FunctionProxy
        
        @param supportedFunctions a Set of Functions
        @param supportedAbstractFunctions a mapping from URI to FunctionProxy
        
        @param superset the superset factory or None'''
        
        # the backing maps for the Function objects
        self.functionMap = {}
    
        # the superset factory chained to this factory
        self.superset = superset
     
        for function in supportedFunctions:
            if function.functionName not in self.functionMap:
                self.functionMap[function.functionName] = function
        
        for functionId in supportedAbstractFunctions.keys():
            proxy = supportedAbstractFunctions.get(functionId)
            self.functionMap[functionId] = proxy
 
    def addFunction(self, function):
        '''Adds the function to the factory. Most functions have no state, so
        the singleton model used here is typically desirable. The factory will
        not enforce the requirement that a Target or Condition matching 
        function must be boolean.
        
        @param function the Function to add to the factory
        @raise TypeError if the function's identifier is already used or if the
        function is non-boolean (when this is a Target or Condition factory)
        '''
        functionId = function.functionId

        # make sure this doesn't already exist
        if functionId in self.functionMap:
            raise TypeError("function %s already exists" % functionId)

        # add to the superset factory
        if self.superset != None:
            self.superset.addFunction(function)

        # Add to this factory
        self.functionMap[functionId] = function
    
    def addAbstractFunction(self, proxy, functionId):
        '''Adds the abstract function proxy to the factory. This is used for
        those functions which have state, or change behaviour (for instance
        the standard map function, which changes its return type based on
        how it is used). 
        
        @param proxy: the FunctionProxy to add to the factory
        @param functionId: the function's identifier
        
        @raise TypeError if the function's identifier is already used'''

        # make sure this doesn't already exist
        if functionId in self.functionMap:
            raise TypeError("function already exists")

        # add to the superset factory
        if self.superset != None:
            self.superset.addAbstractFunction(proxy, functionId)

        # finally, add to this factory
        self.functionMap[functionId] = proxy
    

    def getSupportedFunctions(self): 
        '''Returns the function identifiers supported by this factory.
        
        @return a list of strings'''
    
        functions = self.functionMap.keys()

        if self.superset is not None:
            functions += self.superset.getSupportedFunctions()

        return functions
    
    def createFunction(self, identity):
        '''Tries to get an instance of the specified function.
        
        @param identity the name of the function
        
        @raise UnknownIdentifierException if the name isn't known
        @raise FunctionTypeException if the name is known to map to an
                                      abstract function, and should therefore
                                      be created through createAbstractFunction
        '''
        entry = self.functionMap.get(identity)
        if entry is not None:
            if isinstance(entry, Function):
                return entry
            else:
                # this is actually a proxy, which means the other create
                # method should have been called
                raise FunctionTypeException("function [%s] is abstract" %
                                            identity)    
        else:
            # we couldn't find a match
            raise UnknownIdentifierException("functions of type [%s] are not "
                                             "supported by this factory" % 
                                             identity)
    
    def createAbstractFunction(self, identity, root):
        '''Tries to get an instance of the specified abstract function.
        
        @param identity the name of the function
        @param root the DOM root containing info used to create the function
        @param xpathVersion the version specified in the containing policy, or
                            None if no version was specified
        
        @throws UnknownIdentifierException if the name isn't known
        @throws FunctionTypeException if the name is known to map to a
                                      concrete function, and should therefore
                                      be created through createFunction
        @throws ParsingException if the function can't be created with the
                                 given inputs'''
    
        entry = self.functionMap.get(identity)
        if entry is not None:
            if isinstance(entry, FunctionProxy): 
                try: 
                    return entry.getInstance(root)
                
                except Exception, e:
                    raise ParsingException("Couldn't create abstract function "
                                           "%s: %s" % identity, e)      
            else:
                # this is actually a concrete function, which means that
                # the other create method should have been called
                raise FunctionTypeException("function is concrete")
            
        else:
            raise UnknownIdentifierException("Abstract functions of type %s "
                                             "are not supported by this "
                                             "factory" % identity)

getSupportedFunctions = lambda cls: [cls(i) for i in cls.supportedIdentifiers]

class StandardFunctionFactory(BaseFunctionFactory):
    '''This factory supports the standard set of functions specified in XACML
    1.0 and 1.1. It is the default factory used by the system, and imposes
    a singleton pattern insuring that there is only ever one instance of
    this class.
    <p>
    Note that because this supports only the standard functions, this
    factory does not allow the addition of any other functions. If you call
    addFunction on an instance of this class, an exception
    will be thrown. If you need a standard factory that is modifiable,
    you can either create a new BaseFunctionFactory (or some
    other implementation of FunctionFactory) populated with
    the standard functions from getStandardFunctions or
    you can use getNewFactoryProxy to get a proxy containing
    a new, modifiable set of factories.'''


    # the three singleton instances
    targetFactory = None
    conditionFactory = None
    generalFactory = None

    # the three function sets/maps that we use internally
    targetFunctions = None
    conditionFunctions = None
    generalFunctions = None

    targetAbstractFunctions = None
    conditionAbstractFunctions = None
    generalAbstractFunctions = None

    # the set/map used by each singleton factory instance
    supportedFunctions = None
    supportedAbstractFunctions = None

    
    def __init__(self, supportedFunctions, supportedAbstractFunctions): 
        '''Creates a new StandardFunctionFactory, making sure that the default
        maps are initialized correctly. Standard factories can't be modified,
        so there is no notion of supersetting since that's only used for
        correctly propagating new functions.'''
        super(StandardFunctionFactory, self).__init__(
                        supportedFunctions=supportedFunctions, 
                        supportedAbstractFunctions=supportedAbstractFunctions)

        self.supportedFunctions = supportedFunctions
        self.supportedAbstractFunctions = supportedAbstractFunctions
    
    @classmethod
    def _initTargetFunctions(cls): 
        '''Private initializer for the target functions. This is only ever
        called once.'''
        log.info("Initializing standard Target functions")

        cls.targetFunctions = UniqList()

        # add EqualFunction
        cls.targetFunctions.extend(getSupportedFunctions(EqualFunction))

        # add LogicalFunction
        cls.targetFunctions.extend(getSupportedFunctions(LogicalFunction))
        
        # add NOfFunction
        cls.targetFunctions.extend(getSupportedFunctions(NOfFunction))
        
        # add NotFunction
        cls.targetFunctions.extend(getSupportedFunctions(NotFunction))
        
        # add ComparisonFunction
        cls.targetFunctions.extend(getSupportedFunctions(ComparisonFunction))

        # add MatchFunction
        cls.targetFunctions.extend(getSupportedFunctions(MatchFunction))

        cls.targetAbstractFunctions = {}
    
    @classmethod
    def _initConditionFunctions(cls): 
        '''Private initializer for the condition functions. This is only ever
        called once.'''
        log.info("Initializing standard Condition functions")

        if cls.targetFunctions is None:
            cls._initTargetFunctions()

        cls.conditionFunctions = cls.targetFunctions[:]

        # add condition functions from BagFunction
        try:
            cls.conditionFunctions.extend(
                                getSupportedFunctions(ConditionBagFunction))
        except NotImplementedError:
            log.warning("ConditionBagFunction is not implemented")
        
        try:
            # add condition functions from SetFunction
            cls.conditionFunctions.extend(
                                getSupportedFunctions(ConditionSetFunction))
        except NotImplementedError:
            log.warning("ConditionSetFunction is not implemented")
        
        try:
            # add condition functions from HigherOrderFunction
            cls.conditionFunctions.extend(
                                getSupportedFunctions(HigherOrderFunction))
        except NotImplementedError:
            log.warning("HigherOrderFunction is not implemented")
            
        cls.conditionAbstractFunctions = cls.targetAbstractFunctions.copy()
    
    @classmethod
    def _initGeneralFunctions(cls):     
        '''Private initializer for the general functions. This is only ever
        called once.'''
    
        log.info("Initializing standard General functions")

        if cls.conditionFunctions is None:
            cls._initConditionFunctions()

        cls.generalFunctions = cls.conditionFunctions[:]

        # add AddFunction
        cls.generalFunctions.extend(getSupportedFunctions(AddFunction))
            
        # add SubtractFunction
        cls.generalFunctions.extend(getSupportedFunctions(SubtractFunction))
            
        # add MultiplyFunction
        cls.generalFunctions.extend(getSupportedFunctions(MultiplyFunction))
            
        # add DivideFunction
        cls.generalFunctions.extend(getSupportedFunctions(DivideFunction))
            
        # add ModFunction
        cls.generalFunctions.extend(getSupportedFunctions(ModFunction))
        
        # add AbsFunction
        cls.generalFunctions.extend(getSupportedFunctions(AbsFunction))
            
        # add RoundFunction
        cls.generalFunctions.extend(getSupportedFunctions(RoundFunction))
            
        # add FloorFunction
        cls.generalFunctions.extend(getSupportedFunctions(FloorFunction))
        
        # add DateMathFunction
        cls.generalFunctions.extend(getSupportedFunctions(DateMathFunction))
            
        # add general functions from BagFunction
        cls.generalFunctions.extend(getSupportedFunctions(GeneralBagFunction))
            
        # add NumericConvertFunction
        cls.generalFunctions.extend(getSupportedFunctions(
                                                    NumericConvertFunction))
            
        # add StringNormalizeFunction
        cls.generalFunctions.extend(getSupportedFunctions(
                                                    StringNormalizeFunction))
        
        # add general functions from SetFunction
        cls.generalFunctions.extend(getSupportedFunctions(GeneralSetFunction))
            
        cls.generalAbstractFunctions = cls.conditionAbstractFunctions.copy()

        # Add the map function's proxy
        cls.generalAbstractFunctions[MapFunction.NAME_MAP] = MapFunctionProxy()
    
    @classmethod 
    def getTargetFactory(cls): 
        '''Returns a FunctionFactory that will only provide those functions 
        that are usable in Target matching. This method enforces a singleton
        model, meaning that this always returns the same instance, creating
        the factory if it hasn't been requested before. This is the default
        model used by the FunctionFactory, ensuring quick
        access to this factory.
        
        @return a FunctionFactory for target functions'''
        if cls.targetFactory is None: 
            if cls.targetFunctions is None:
                cls._initTargetFunctions()
                
            if cls.targetFactory is None:
                cls.targetFactory=cls(cls.targetFunctions,
                                      cls.targetAbstractFunctions)
        
        return cls.targetFactory

    
    @classmethod
    def getConditionFactory(cls): 
        '''Returns a FuntionFactory that will only provide those functions that
        are usable in the root of the Condition. These Functions are a
        superset of the Target functions. This method enforces a singleton
        model, meaning that this always returns the same instance, creating
        the factory if it hasn't been requested before. This is the default
        model used by the FunctionFactory, ensuring quick
        access to this factory.
    
        @return a FunctionFactory for condition functions
        '''
        if cls.conditionFactory is None:
            if cls.conditionFunctions is None:
                cls._initConditionFunctions()
                
            if cls.conditionFactory is None:
                cls.conditionFactory = cls(cls.conditionFunctions,
                                           cls.conditionAbstractFunctions)       

        return cls.conditionFactory
    

    @classmethod
    def getGeneralFactory(cls): 
        '''Returns a FunctionFactory that provides access to all the functions.
        These Functions are a superset of the Condition functions. This method
        enforces a singleton model, meaning that this always returns the same
        instance, creating the factory if it hasn't been requested before.
        This is the default model used by the FunctionFactory,
        ensuring quick access to this factory.
        
        @return a FunctionFactory for all functions'''
    
        if cls.generalFactory is None:
            if cls.generalFunctions is None:
                cls._initGeneralFunctions()
                
                cls.generalFactory = cls(cls.generalFunctions,
                                         cls.generalAbstractFunctions)
                
        return cls.generalFactory


    def getStandardFunctions(self):
        '''Returns the set of functions that this standard factory supports.
        
        @return a Set of Functions'''
        return tuple(self.supportedFunctions.keys())
        
    def getStandardAbstractFunctions(self):
        '''Returns the set of abstract functions that this standard factory
        supports as a mapping of identifier to proxy.
        
        @return a Map mapping URIs to FunctionProxys'''
        return tuple(self.supportedAbstractFunctions.keys())
    
    
    @classmethod
    def getNewFactoryProxy(cls): 
        '''A convenience method that returns a proxy containing newly created
        instances of BaseFunctionFactorys that are correctly
        supersetted and contain the standard functions and abstract functions.
        These factories allow adding support for new functions.
        
        @return a new proxy containing new factories supporting the standard
        functions'''
        
        general = cls.getGeneralFactory()
            
        newGeneral=BaseFunctionFactory(general.getStandardFunctions(),
                                       general.getStandardAbstractFunctions())

        condition = cls.getConditionFactory()
        
        newCondition = BaseFunctionFactory(newGeneral,
                                    condition.getStandardFunctions(),
                                    condition.getStandardAbstractFunctions())

        target = cls.getTargetFactory()
        newTarget = BaseFunctionFactory(newCondition,
                                    target.getStandardFunctions(),
                                    target.getStandardAbstractFunctions())

        return BasicFunctionFactoryProxy(newTarget, newCondition, newGeneral)
    
    def addFunction(self, function):
        '''Always throws an exception, since support for new functions may not 
        be added to a standard factory.
        
        @param function the Function to add to the factory       
        @raise NotImplementedError'''
    
        raise NotImplementedError("a standard factory cannot support new "
                                  "functions")
    
    
    def addAbstractFunction(self, proxy, identity):
        '''Always throws an exception, since support for new functions may not 
        be added to a standard factory.
        
        @param proxy the FunctionProxy to add to the factory
        @param identity the function's identifier
        
        @raise NotImplementedError always'''
        raise NotImplementedError("a standard factory cannot support new "
                                  "functions")
