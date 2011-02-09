#
# NERC Data Grid Project
#
# @author P J Kershaw 27/02/07
#
# Generate SysV init scripts from ndg-aa template
#
# @copyright (C) 2007 CCLRC & NERC
#
# @license This software may be distributed under the terms of the Q Public 
# License, version 1.0 or later.
#
# $Id:$
TEMPL_FILE=ndg-aa
SCRIPT_FILES=ndg-sm ndg-ca ndg-gk ndg-log
NAME_SUB=Attribute Authority
CODE_SUB=attAuthority
ENV_SUB=AA

generateScripts:
	@echo -n "Making script files ${SCRIPT_FILES} from ${TEMPL_FILE} ... "
	@NAME_REPL=( "Session Manager" ); \
	CODE_REPL=( sessionMgr  ); \
	ENV_REPL=( SM ); \
	j=0; \
	for i in ${SCRIPT_FILES}; do \
	    cat ${TEMPL_FILE}|\
	    sed  s/"${NAME_SUB}"/"$${NAME_REPL[j]}"/g |\
	    sed s/"${CODE_SUB}"/"$${CODE_REPL[j]}"/g |\
	    sed s/"${ENV_SUB}"/"$${ENV_REPL[j]}"/g> $$i; \
	    let "j++"; \
	done;
	@echo done.

clean:
	rm -f ${SCRIPT_FILES}
