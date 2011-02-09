"""NDG Logging class

NERC Data Grid Project

P J Kershaw 10/05/06

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

reposID = '$Id$'

import logging
from logging.handlers import *

# Inherit directly from Logger
_logSuperClass = logging.getLoggerClass()


#_____________________________________________________________________________
class LogError(Exception):
    """Exception handling for NDG Logging class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg


#_____________________________________________________________________________
class Log(_logSuperClass):
    """NDG Logging class"""
    
    __msgFmt = '%(asctime)s %(name)s: %(levelname)-8s %(message)s'
    __dateFmt = '%d %b %Y %H:%M:%S'
    
    # Log file size limit and number of backups saved
    __maxBytes = 1048576
    __backUpCnt = 10
    
    def __init__(self, logName='', logFilePath=None, console=False):
        """NDG Logging class
        
        logName:        provide a log name 
        logFilePath:    if set, write to a log file given by the path
        console:        Set to True to send output to the stderr"""

        # Inherit from Logger class
        _logSuperClass.__init__(self, logName, level=logging.DEBUG)
                            
        
        # Set a format for messages
        formatter = logging.Formatter(fmt=self.__msgFmt, 
                                      datefmt=self.__dateFmt)


        # Handler set to write to INFO messages or higher to the sys.stderr
        if console:
            console = logging.StreamHandler()
            console.setLevel(logging.INFO)
        
            # Set the handler to use format set earlier
            console.setFormatter(formatter)
    
            # Add the handler to this log object
            self.addHandler(console)
        
        
        # Log file set with rotating file handler.  When log size > than
        # maxBytes, a new log file is started.  Up to backupCount are created
        # before the first is overwritten
        if logFilePath:
            fileLog = RotatingFileHandler(logFilePath, 
                                          maxBytes=self.__maxBytes, 
                                          backupCount=self.__backUpCnt)
            fileLog.setFormatter(formatter)
            
            # Nb. log file includes debug messages
            fileLog.setLevel(logging.DEBUG)
            
            self.addHandler(fileLog)
