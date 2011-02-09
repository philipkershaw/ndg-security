#
# NERC Data Grid Project
#
# @author P J Kershaw 15/03/07
#
# Make all eggs
#
# @copyright: (C) 2007 CCLRC & NERC
#
# @license: This software may be distributed under the terms of the Q Public
# License, version 1.0 or later.
#
# $Id$
EGG_DIRS=ndg.security.common ndg.security.client ndg.security.server \
ndg.security.test .

# Override on the command line for alternative path
PYTHON=python

eggs:
	@-for dir in ${EGG_DIRS}; do \
		cd $$dir; \
		${PYTHON} setup.py bdist_egg; \
		cd ..; \
	done;

clean:
	@-for dir in ${EGG_DIRS}; do \
		cd $$dir; \
		rm -f dist/*.egg; \
		rm -rf *.egg-info; \
		rm -rf build; \
		cd ..; \
	done;

replace: clean eggs

# Convenient alias
force: replace

NDG_EGG_DIST_USER=
NDG_EGG_DIST_HOST=
NDG_EGG_DIST_DIR=

install_eggs: eggs
	scp ndg-security-install.py dist/*.egg ndg.*/dist/*.egg \
	${NDG_EGG_DIST_USER}@${NDG_EGG_DIST_HOST}:${NDG_EGG_DIST_DIR}

# Make ZSI stubs from Session Manager WSDL
SM_ZSI_STUB_DIRS=./ndg.security.server/ndg/security/server/SessionMgr \
				 ./ndg.security.common/ndg/security/common/SessionMgr

sm_zsi_wsdl_stubs:
	@-for dir in ${SM_ZSI_STUB_DIRS}; do \
		cd $$dir && make && cd ../../../../..; \
	done;

# Make ZSI stubs from Attribute Authority WSDL
AA_ZSI_STUB_DIRS=./ndg.security.server/ndg/security/server/AttAuthority \
				 ./ndg.security.common/ndg/security/common/AttAuthority
				 
aa_zsi_wsdl_stubs:
	@-for dir in ${AA_ZSI_STUB_DIRS}; do \
		cd $$dir && make && cd ../../../../..; \
	done;

# Make all ZSI stubs for NDG security
zsi_wsdl_stubs: sm_zsi_wsdl_stubs aa_zsi_wsdl_stubs


# Generate HTML from embedded epydoc text in source code.
EPYDOC=epydoc
EPYDOC_OUTDIR=../documentation/epydoc
EPYDOC_NAME='NDG Security'
EPYDOC_LOGFILE=epydoc.log
EPYDOC_FRAMES_OPT=--no-frames
epydoc:
	${EPYDOC} ./ndg.security.*/ndg -o ${EPYDOC_OUTDIR} \
	--name ${EPYDOC_NAME} ${EPYDOC_FRAMES_OPT} --include-log --graph=all -v \
	>& ${EPYDOC_LOGFILE}
	
# Generate SysV init scripts for Twisted based services
init_scripts:
	cd ./ndg.security.server/ndg/security/server/share && make generateScripts

