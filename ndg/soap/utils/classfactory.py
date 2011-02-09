"""
Generic parsers to use when reading in configuration data
- methods available to deal with both XML and INI (flat text key/val) formats
"""
__author__ = "C Byrom (Tessella), P J Kershaw (STFC)"
__date__ = "28/08/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import traceback
import logging, os, sys
log = logging.getLogger(__name__)


class ClassFactoryError(Exception):
    """Exception handling for NDG classfactory module."""
    def __init__(self, msg):
        log.error(msg)
        Exception.__init__(self, msg)


def importClass(moduleName, className=None, objectType=None):
    '''Import a class from a string module name and class name.
    
    @param moduleName: Name of module containing the class
    @type moduleName: str 
    @param className: Name of the class to import.  If none is given, the 
    class name will be assumed to be the last component of modulePath
    @type className: str
    @rtype: class object
    @return: imported class'''
    
    if className is None:
        _moduleName, className = moduleName.rsplit('.', 1)
    else:
        _moduleName = moduleName
    
    log.debug("Importing class %s ..." % className) 
      
    module = __import__(_moduleName, globals(), locals(), [])
    components = _moduleName.split('.')
    try:
        for component in components[1:]:
            module = getattr(module, component)
    except AttributeError:
        raise AttributeError("Error importing class %s: %s" %
                             (className, traceback.format_exc()))

    importedClass = getattr(module, className)

    # Check class inherits from a base class
    if objectType and not issubclass(importedClass, objectType):
        raise TypeError("Specified class %s must be derived from %s; got %s" %
                        (className, objectType, importedClass))
    
    log.info('Imported "%s" class from module, "%s"', className, _moduleName)
    return importedClass
    

def instantiateClass(moduleName, className=None, moduleFilePath=None, 
                     objectType=None, classArgs=(), classProperties={}):
    '''
    Create and return an instance of the specified class
    @param moduleName: Name of module containing the class
    @type moduleName: str 
    @param className: Name of the class to instantiate.  May be None in 
    which case, the class name is parsed from the moduleName last element
    @type className: str
    @param moduleFilePath: Path to the module - if unset, assume module on 
    system path already
    @type moduleFilePath: str
    @param classProperties: dict of properties to use when instantiating the 
    class
    @type classProperties: dict
    @param objectType: expected type for the object to instantiate - to 
    enforce use of specific interfaces 
    @type objectType: object
    @return: object - instance of the class specified 
    '''

    
    # ensure that classproperties is a dict - NB, it may be passed in as a null
    # value which can override the default val
    if not isinstance(classProperties, dict):
        raise TypeError("Expecting dict type for 'classProperties' attribute; "
                        "got %r" % type(classProperties))

    # variable to store original state of the system path
    sysPathBak = None
    try:
        try:
            # Module file path may be None if the new module to be loaded
            # can be found in the existing system path            
            if moduleFilePath:
                if not os.path.exists(moduleFilePath):
                    raise IOError("Module file path '%s' doesn't exist" % 
                                  moduleFilePath)
                          
                # Temporarily extend system path ready for import
                sysPathBak = sys.path
                          
                sys.path.append(moduleFilePath)

            
            # Import module name specified in properties file
            importedClass = importClass(moduleName, 
                                        className=className,
                                        objectType=objectType)
        finally:
            # revert back to original sys path, if necessary
            # NB, python requires the use of a try/finally OR a try/except 
            # block - not both combined
            if sysPathBak:
                sys.path = sysPathBak
                            
    except Exception, e:
        log.error('%s module import raised %s type exception: %s' % 
                  (moduleName, e.__class__, e))
        raise 

    # Instantiate class
    log.debug('Instantiating class "%s"' % importedClass.__name__)
    try:
        if classArgs:
            object = importedClass(*classArgs, **classProperties)
        else:
            object = importedClass(**classProperties)
            
        return object

    except Exception, e:
        log.error("Instantiating class, %s: %s" % (importedClass.__name__, 
                                                   traceback.format_exc()))
        raise