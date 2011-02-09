#
# NERC Data Grid Project
#
# @author P J Kershaw 01/10/08
#
# Generate web service stubs from WSDL for Attribute Authority client and
# server side code
#
# @copyright (C) 2008 STFC
#
# @license This software may be distributed under the terms of the Q Public 
# License, version 1.0 or later.
#
# $Id:$
WSDL_FILE=./attributeauthority.wsdl
CMD=wsdl2py
OPTS=-be -f

generateStubs: ${WSDL_FILE}
	@echo Generate stub ...
	${CMD} ${OPTS} ${WSDL_FILE}
	@echo Done.
	