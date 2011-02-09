"""
Generic parsers to use when reading in configuration data
- methods available to deal with both XML and INI (flat text key/val) formats
"""
__author__ = "C Byrom - Tessella"
__date__ = "28/08/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import logging, os, sys
log = logging.getLogger(__name__)

class ClassFactoryError(Exception):
    """Exception handling for NDG classfactory module."""
    def __init__(self, msg):
        log.error(msg)
        Exception.__init__(self, msg)


def instantiateClass(moduleName, className, moduleFilePath=None, 
                     objectType=None, classProperties={}):
    '''
    Create and return an instance of the specified class
    @param moduleName: Name of module containing the class
    @type moduleName: str 
    @param className: Name of the class to instantiate
    @type className: str
    @keyword moduleFilePath: Path to the module - if unset, assume module on 
    system path already
    @type moduleFilePath: str
    @keyword classProperties: dict of properties to use when instantiating the 
    class
    @type classProperties: dict
    @keyword objectType: expected type for the object to instantiate - to 
    enforce use of specific interfaces 
    @type objectType: object
    @return: object - instance of the class specified 
    '''

    log.debug("Instantiating class, %s" % className)
    
    # ensure that classproperties is a dict - NB, it may be passed in as a null
    # value which can override the default val
    if not classProperties:
        classProperties = {}

    # variable to store original state of the system path
    sysPathBak = None
    try:
        try:
            # Module file path may be None if the new module to be loaded
            # can be found in the existing system path            
            if moduleFilePath:
                if not os.path.exists(moduleFilePath):
                    raise IOError("Module file path '%s' doesn't exist" % \
                                  moduleFilePath)
                          
                # Temporarily extend system path ready for import
                sysPathBak = sys.path
                          
                sys.path.append(moduleFilePath)

#            from paste.util.import_string import eval_import
#            mod = eval_import(moduleName)
            
            # Import module name specified in properties file
            importModule=__import__(moduleName,globals(),locals(),[className])

            #importClass = getattr(importModule, className)
            importClass = eval('importModule.'+className)
        finally:
            # revert back to original sys path, if necessary
            # NB, python requires the use of a try/finally OR a try/except 
            # block - not both combined
            if sysPathBak:
                sys.path = sysPathBak
                            
    except Exception, e:
        raise ClassFactoryError('Error importing %s module: %s'%(moduleName,e))

    # Check class inherits from AAproxy abstract base class
    if objectType and not issubclass(importClass, objectType):
        raise ClassFactoryError("Specified class %s must be derived from %s" %
                                (className, objectType))

    # Instantiate class
    try:
        object = importClass(**classProperties)
        log.info('Instantiated "%s" class from module, "%s"' % (className,
                                                                moduleName))
        return object

    except Exception, e:
        log.error("Error instantiating class, %s: %s"%(importClass.__name__,e))
        raise
            
                 
