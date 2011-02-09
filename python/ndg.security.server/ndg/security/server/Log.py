"""NDG Logging class

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "10/05/06"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

import os
import logging
from logging.handlers import RotatingFileHandler, SysLogHandler


# Inherit directly from Logger
_logSuperClass = logging.getLoggerClass()


#_____________________________________________________________________________
class LogError(Exception):
    """Exception handling for NDG Logging class."""

#_____________________________________________________________________________
class Log(_logSuperClass):
    """NDG Security Logging class"""
    
    msgFmt = '%(asctime)s %(name)s: %(levelname)-8s %(message)s'
    dateFmt = '%d %b %Y %H:%M:%S'
    
    # Log file size limit and number of backups saved
    maxBytes = 1048576
    backUpCnt = 10
    
    def __init__(self, name=None, sysLogHandlerKw={}):
        """NDG Logging class
        
        logName:        provide a log name 
        logFilePath:    if set, write to a log file given by the path
        console:        Set to True to send output to the stderr"""

        logDebug = bool(os.environ.get("NDGSEC_LOGDEBUG"))
        
        # Inherit from Logger class
        _logSuperClass.__init__(self, name=name, level=logging.DEBUG)
                            
        
        # Set a format for messages
        formatter = logging.Formatter(fmt=self.msgFmt, datefmt=self.dateFmt)


        # Handler set to write to INFO messages or higher to the sys.stderr
        if os.environ.get("NDGSEC_CONSOLELOG"):
            console = logging.StreamHandler()
            console.setLevel(logging.INFO)
        
            # Set the handler to use format set earlier
            console.setFormatter(formatter)
    
            # Add the handler to this log object
            self.addHandler(console)
        
        
        # Log file set with rotating file handler.  When log size > than
        # maxBytes, a new log file is started.  Up to backupCount are created
        # before the first is overwritten
        logFilePath = os.environ.get("NDGSEC_LOGFILEPATH")
        if logFilePath:
            fileLog = RotatingFileHandler(logFilePath, 
                                          maxBytes=self.maxBytes, 
                                          backupCount=self.backUpCnt)
            fileLog.setFormatter(formatter)
            
            # Nb. log file includes debug messages
            if logDebug: fileLog.setLevel(logging.DEBUG)
            
            self.addHandler(fileLog)
            
        if os.environ.get("NDGSEC_SYSLOG"):
            sysLogHandler = SysLogHandler(**sysLogHandlerKw)
            sysLogHandler.setFormatter(formatter)
            
            if logDebug: sysLogHandler.setLevel(logging.DEBUG)
            
            self.addHandler(sysLogHandler)

# Make NDG Security Logger the default
logging.setLoggerClass(Log)

log = Log()