#
# NERC Data Grid Project
#
# @author P J Kershaw 25/01/07
#
# Generate web service stubs from WSDL for Session Manager client and
# server side code
#
# @copyright (C) 2007 CCLRC & NERC
#
# @license This software may be distributed under the terms of the Q Public 
# License, version 1.0 or later.
#
# $Id:$
WSDL_FILE=../../../../../www/html/sessionMgr.wsdl
CMD=wsdl2dispatch
OPTS=-e -f

STUB_FILE=SessionMgr_services_server.py
TMP_FILE=SessionMgr_services_server.py.tmp

ORIG1=return result
REPL1=return self.request, result
ORIG2=from SessionMgr_services import
REPL2=from ndg.security.common.SessionMgr.SessionMgr_services import

generateStubs: ${WSDL_FILE}
	@echo Generate stub ...
	${CMD} ${OPTS} ${WSDL_FILE}
	@echo Make substitutions for compatibility with Twisted and for \
correct NDG import ...
	@cat ${STUB_FILE}|sed  s/"${ORIG1}"/"${REPL1}"/g | \
	sed s/"${ORIG2}"/"${REPL2}"/g > ${TMP_FILE}
	@mv ${TMP_FILE} ${STUB_FILE}
	@echo Done.
