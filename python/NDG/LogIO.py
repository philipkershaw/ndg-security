"""NDG Logger Web Service helper classes for I/O between client
and server

NERC Data Grid Project

P J Kershaw 12/05/06

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

svnID = '$Id$'
        
from XMLMsg import *


class DebugReq(XMLMsg):
    xmlTagTmpl = {'msg': ''}
    xmlMandatoryTags = ['msg']
    
class InfoReq(DebugReq):
    pass
 
class WarningReq(DebugReq):
    pass
    
class ErrorReq(DebugReq):
    pass