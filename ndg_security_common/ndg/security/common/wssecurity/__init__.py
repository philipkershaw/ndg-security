"""NDG Security WS-Security package - contains signature handler and config

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "01/04/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

import os

from ConfigParser import SafeConfigParser
from os.path import expandvars as exVar
import copy
from ZSI.wstools.Namespaces import OASIS

from ndg.security.common.utils.configfileparsers import \
    CaseSensitiveConfigParser

class WSSecurityError(Exception):
    """For WS-Security generic exceptions not covered by other exception
    classes in this module"""
    def __init__(self, errorMessage):
        log.error(errorMessage)
        super(WSSecurityError, self).__init__(errorMessage)
        
class WSSecurityConfigError(WSSecurityError):
    """Configuration error with WS-Security setting or settings"""
    
class WSSecurityConfigOpNotPermitted(WSSecurityConfigError):
    "Raise for dict methods not allowed in WSSecurityConfig"
    
class WSSecurityConfig(dict):
    """Parser for WS-Security configuration.  Extends dict to enable
    convenient interface for access to params.
    """
    propertyDefaults = dict(
        reqBinSecTokValType=OASIS.X509TOKEN.X509,
        verifyingCert=None,
        verifyingCertFilePath=None,
        signingCert=None,
        signingCertFilePath=None, 
        signingCertChain=[],
        signingPriKey=None,
        signingPriKeyFilePath=None, 
        signingPriKeyPwd=None,
        caCertDirPath=None,
        caCertFilePathList=[],
        addTimestamp=True,
        timestampClockSkew=0.,
        timestampMustBeSet=False,
        createdElemMustBeSet=True,
        expiresElemMustBeSet=True,
        applySignatureConfirmation=False,
        refC14nInclNS=[],
        signedInfoC14nInclNS=[])
    
    def __init__(self, cfg=SafeConfigParser()):
        '''Initialise settings from an existing config file object or the
        given path to config file
        
        @type cfg: SafeConfigParser or string
        @param cfg: config object instance or file path to config file to be
        parsed'''
        
        dict.__init__(self)
        
        # Initialise parameters from ref in class var
        self._param = WSSecurityConfig.propertyDefaults.copy()
        
        if isinstance(cfg, basestring):
            # Assume file path to be read
            self.read(cfg)
        else:
            # Assume existing config type object
            self._cfg = cfg
        

    def read(self, filePath):
        '''Read ConfigParser object
        
        @type filePath: basestring
        @param filePath: file to read config from'''
        
        # Expand environment variables in file path
        expandedFilePath = exVar(filePath)
        
        # Add 'here' item to enable convenient path substitutions in the config
        # file
        defaultItems = dict(here=os.path.dirname(expandedFilePath))
        self._cfg = CaseSensitiveConfigParser(defaults=defaultItems)
        
        readFilePaths = self._cfg.read(expandedFilePath)
        
        # Check file was read in OK
        if len(readFilePaths) == 0:
            raise IOError('Missing config file: "%s"' % expandedFilePath)

    def parse(self, **kw):
        '''Extract items from config file and place in dict
        @type **kw: dict
        @param **kw: this enables WS-Security params to be set in a config file
        with other sections e.g. params could be under the section 'wssecurity'
        '''
        section = kw.pop('section', 'DEFAULT')
        
        # Prefix for option names - optNames = name as they appear in the 
        # config file, self._param are the names used in the code.
        prefix = kw.pop('prefix', None)

        if prefix:
            optNames = ["%s.%s" % (prefix, optName) for optName in self._param] 
        else:
            optNames = self._param
            
        for optName, paramName in zip(optNames, self._param):
            
            # Parameters may be omitted and set later
            if self._cfg.has_option(section, optName):
                if isinstance(WSSecurityConfig.propertyDefaults[paramName], 
                              list):
                    try:
                        self._param[paramName] = \
                            exVar(self._cfg.get(section, optName)).split()
                    except AttributeError:
                        raise WSSecurityConfigError('Setting "%s"' % paramName)
                    
                elif isinstance(WSSecurityConfig.propertyDefaults[paramName], 
                                bool):           
                    self._param[paramName] = self._cfg.getboolean(section, 
                                                                  optName)
                else:
                    # Default to None if setting is an empty string.  Settings
                    # of '' causes problems for M2Crypto parsing
                    self._param[paramName] = \
                        exVar(self._cfg.get(section, optName)) or None

    def __len__(self):
        return len(self._param)
    
    def __iter__(self):
        return self._param.__iter__()
    
    def __repr__(self):
        """Return file properties dictionary as representation"""
        return repr(self._param)

    def __delitem__(self, key):
        "Session Manager keys cannot be removed"        
        raise KeyError('Keys cannot be deleted from ' + \
                        WSSecurityConfig.__name__)

    def __getitem__(self, key):
        WSSecurityConfig.__name__ + \
        """ behaves as data dictionary of WS-Security properties
        """
        if key not in WSSecurityConfig.propertyDefaults:
            raise KeyError("Invalid key '%s'" % key)
        
        return self._param[key]  
    
    def __setitem__(self, key, item):
        WSSecurityConfig.__name__ + \
        """ behaves as data dictionary of WS-Security properties"""
        if key not in WSSecurityConfig.propertyDefaults:
            raise KeyError("Parameter key '%s' is not recognised" % key)
        
        self._param[key] = item

    def copy(self):
        wsSecurityConfig = WSSecurityConfig()
        wsSecurityConfig._param = self._param.copy()
        return wsSecurityConfig
    
    def get(self, key, *arg):
        return self._param.get(key, *arg)

    def clear(self):
        raise WSSecurityConfigOpNotPermitted("Data cannot be cleared from "+\
                                             WSSecurityConfig.__name__)
   
    def keys(self):
        return self._param.keys()

    def items(self):
        return self._param.items()

    def values(self):
        return self._param.values()

    def has_key(self, key):
        return self._param.has_key(key)

    # 'in' operator
    def __contains__(self, key):
        return key in self._param
    
    def update(self, seq, *arg, **kw):

        # Prefix for option names - optNames = name as they appear in the 
        # config file, self._param are the names used in the code.
        prefix = kw.pop('prefix', None)
        if prefix:
            pfxWithDot = prefix+'.'
            seqFilt = dict([(k.replace(pfxWithDot, ''), v) 
                            for k, v in seq.items() 
                            if k.startswith(pfxWithDot)])
        else:
            seqFilt = seq
        
        badKeys = []
        for optName, optVal in seqFilt.items():
            if optName not in WSSecurityConfig.propertyDefaults:
                badKeys += [optName]
                
            elif isinstance(WSSecurityConfig.propertyDefaults[optName], list):
                if isinstance(optVal, basestring):
                    # Parse into a list
                    seqFilt[optName] = exVar(optVal).split()
                elif isinstance(optVal, list):
                    seqFilt[optName] = exVar(optVal)
                else:
                    raise WSSecurityConfigError("Expecting list type for "
                                                'option "%s"' % optName)
            elif isinstance(WSSecurityConfig.propertyDefaults[optName], bool):
                if isinstance(optVal, basestring):
                    # Parse into a boolean
                    seqFilt[optName] = bool(optVal)
                    
                elif isinstance(optVal, bool):
                    seqFilt[optName] = optVal
                else:
                    raise WSSecurityConfigError("Expecting bool type for "
                                                'option "%s"' % optName)
            else:
                # Default to None if setting is an empty string.  Settings
                # of '' causes problems for M2Crypto parsing
                if optVal is None:
                    seqFilt[optName] = optVal
                else:
                    seqFilt[optName] = exVar(optVal) or None
                
        if len(badKeys) > 0:
            log.warning("Ignoring unrecognised parameter key(s) for update: "
                        "%s" % ', '.join(badKeys))

        return self._param.update(seqFilt, *arg)
    
    def fromkeys(self, seq):
        badKeys=[i for i in seq if i not in WSSecurityConfig.propertyDefaults]
        if badKeys:
            raise KeyError("Parameter key(s) %s not recognised" % 
                           ','.join(badKeys))
        return self._param.fromkeys(seq)
    
    def setdefault(self, key, *arg):
        badKeys=[i for i in arg if i not in WSSecurityConfig.propertyDefaults]
        if badKeys:
            raise KeyError("Parameter keys '%s' not recognised" % badKeys)
        return self._param.setdefault(key, *arg)

    def pop(self, key, *arg):
        raise WSSecurityConfigOpNotPermitted("Params should not be deleted")
    
    def popitem(self):
        raise WSSecurityConfigOpNotPermitted("Params should not be deleted")
    
    def iteritems(self):
        return self._param.iteritems()
    
    def iterkeys(self):
        return self._param.iterkeys()
    
    def itervalues(self):
        return self._param.itervalues()
   