"""NDG Security wssecurity package - contains signature handler and config

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "01/04/08"
__copyright__ = "(C) 2008 STFC & NERC"
__contact__ = "P.J.Kershaw@rl.ac.uk"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = "$Id$"

from ZSI.wstools.Namespaces import OASIS
from ConfigParser import SafeConfigParser
from os.path import expandvars as exVar
import copy

class WSSecurityConfigOpNotPermitted(Exception):
    "Raise for dict methods not allowed in WSSecurityConfig"
    
class WSSecurityConfig(dict):
    """Parser for WS-Security configuration.  Extends dict to enable
    convenient interface for access to params.
    """
    defParam = dict(
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
             applySignatureConfirmation=False,
             refC14nKw={'unsuppressedPrefixes': []},
             refC14nInclNS=[],
             signedInfoC14nKw = {'unsuppressedPrefixes': []},
             signedInfoC14nInclNS=[])
    
    def __init__(self, cfg=SafeConfigParser()):
        '''Initialise settings from an existing config file object or the
        given path to config file
        
        @type cfg: SafeConfigParser or string
        @param cfg: config object instance or file path to config file to be
        parsed'''
        
        dict.__init__(self)
        
        # Initialise parameters from ref in class var
        self._param = WSSecurityConfig.defParam.copy()
        
        if isinstance(cfg, basestring):
            # Assume file path to be read
            self.read(cfg)
        else:
            # Assume existing config type object
            self._cfg = cfg
        

    def read(self, *arg):
        '''Read ConfigParser object'''
        self._cfg = SafeConfigParser()
        self._cfg.read(*arg)


    def parse(self, **kw):
        '''Extract items from config file and place in dict
        @type **kw: dict
        @param **kw: this enables WS-Security params to be set in a config file
        with other sections e.g. params could be under the section 'wssecurity'
        '''
        if 'section' in kw:
            section = kw['section']
        else:
            section = 'DEFAULT'
             
        for paramName in self._param:
            # Options may be omitted and set later
            if self._cfg.has_option(section, paramName):
                # Switch based defParam type - TODO: refC14nKw and 
                # signedInfoC14nKw - maybe these should be removed as they're
                # clumsy
                if isinstance(WSSecurityConfig.defParam[paramName], list):
                    try:
                        self._param[paramName] = \
                            exVar(self._cfg.get(section, paramName)).split()
                    except AttributeError:
                        raise SecurityConfigError('Setting "%s"' % paramName)
                    
                elif isinstance(WSSecurityConfig.defParam[paramName], bool):           
                    self._param[paramName] = self._cfg.getboolean(section, 
                                                                  paramName)
                else:
                    # Default to None if setting is an empty string.  Settings
                    # of '' causes problems for M2Crypto parsing
                    self._param[paramName] = \
                        exVar(self._cfg.get(section, paramName)) or None

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
        if key not in self.defParam:
            raise KeyError("Invalid key '%s'" % key)
        
        return self._param[key]  
    
    def __setitem__(self, key, item):
        WSSecurityConfig.__name__ + \
        """ behaves as data dictionary of WS-Security properties"""
        if key not in WSSecurityConfig.defParam:
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
    
    def update(self, seq, *arg):
        badKeys = [i for i in seq if i not in WSSecurityConfig.defParam]
        if badKeys:
            raise KeyError("Parameter key(s) %s not recognised" % \
                           ','.join(badKeys))
        return self._param.update(seq, *arg)
    
    def fromkeys(self, seq):
        badKeys = [i for i in seq if i not in WSSecurityConfig.defParam]
        if badKeys:
            raise KeyError("Parameter key(s) %s not recognised" % \
                           ','.join(badKeys))
        return self._param.fromkeys(*arg)
    
    def setdefault(self, key, *arg):
        badKeys = [i for i in b if i not in WSSecurityConfig.defParam]
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

# Temporary measure - until...
# TODO: Move wsSecurity module into this package
from ndg.security.common.wsSecurity import *
   