#______________________________________________________________________________
#
# Makefile for Attribute Authority installation
#
# make -f attAuthority.mk [MOD_DIR=<module target dir>|NDG_DIR=<NDG dir>|
#			CVSROOT=<cvs root dir>|CVS_REL=<cvs release ID>]
#
# NERC Data Grid Project
# 
# P J Kershaw 15/04/05
# 
# Copyright (C) 2005 CCLRC & NERC
#
# This software may be distributed under the terms of the Q Public License,
# version 1.0 or later.
#
# $Id$
#______________________________________________________________________________
SHELL=/bin/sh
RM=rm 
CP=cp
MKDIR=mkdir
ECHO=echo
DIRNAME=dirname
CVS=cvs

# Export from most up to date verision using '-D' - Could change to -r and use
# a revision tag
CVS_REL=
#CVS_EXPORT=cvs export -r $(CVS_REL)
CVS_EXPORT=cvs export -D "`date`"
CVS_PYSEC_DIR=security/python
CVS_PYSECNDG_DIR=$(CVS_PYSEC_DIR)/NDG

# If required, override MOD_DIR with command line argument to make:
#
# make -f attAuthority MOD_DIR=/usr/local/python2.4/site-packages
MOD_DIR=$(HOME)/python
MOD_NDG_DIR=$(MOD_DIR)/NDG

NDG_DIR=$(HOME)/NDG
NDG_CONFIG_DIR=$(NDG_DIR)/config

NDG_CONFIG_FILES=	attAuthorityProperties.xml \
			attAuthority.wsdl \
			mapConfig.xml

NDG_MOD_FILES=	__init__.py \
		AttAuthority.py \
		AttAuthorityServer.py \
		attAuthority_services.py \
		AttCert.py \
		xmlSigDoc.py \
		X509.py \
		TestUserRoles.py


install:	chkenv installmkdirs cvsexport installdone


installmkdirs:
	@$(ECHO) _______________________________________________________________
	@$(ECHO) NDG Attribute Authority Installation
	@$(ECHO) _______________________________________________________________
	@$(ECHO) -n "Creating module target directory '$(MOD_NDG_DIR)' ... "
	@-$(MKDIR) $(MOD_DIR) 2>/dev/null
	@-$(MKDIR) $(MOD_NDG_DIR) 2>/dev/null
	@$(ECHO) done. 
	@$(ECHO) -n \
		"Creating NDG configuration directory '$(NDG_DIR)/config' ... "
	@-$(MKDIR) $(NDG_DIR) 2>/dev/null
	@-$(MKDIR) $(NDG_DIR)/config 2>/dev/null
	@$(MKDIR) $(NDG_DIR)/config/certs $(NDG_DIR)/config/attCert
	@$(ECHO) done. 
	@$(ECHO)


cvsexport: cleancvsexport
	@$(ECHO) Exporting files from CVS ...
	@-for i in ${NDG_CONFIG_FILES}; do \
		($(CVS_EXPORT) -d $(NDG_DIR)/config $(CVS_PYSEC_DIR)/$$i); \
	done
	@-for i in ${NDG_MOD_FILES}; do \
		($(CVS_EXPORT) -d $(MOD_NDG_DIR) $(CVS_PYSECNDG_DIR)/$$i); \
	done
	@chmod 775 $(MOD_NDG_DIR)/AttAuthorityServer.py
	@$(ECHO)
	@$(ECHO) Export complete.


installdone:
	@$(ECHO)
	@$(ECHO) Installation complete.
	@$(ECHO) _______________________________________________________________
    

# Keep rm arguments separate from macro to try avoid mailicous use
clean:	cleaninit cleancvsexport
	@$(RM) -ir $(MOD_NDG_DIR)
	@$(RM) -ir $(NDG_DIR)/config
	@$(ECHO)
	@$(ECHO) Uninstall complete.
	@$(ECHO) _______________________________________________________________


cleaninit:
	@$(ECHO) _______________________________________________________________
	@$(ECHO) NDG Attribute Authority Uninstall
	@$(ECHO) _______________________________________________________________


cleancvsexport: chkenv
	@$(ECHO) -n "Removing cvs exported files ... "
	@for i in ${NDG_CONFIG_FILES}; do \
		($(RM) -f $(NDG_DIR)/config/$$i); \
	done
	@for i in ${NDG_MOD_FILES}; do \
		($(RM) -f $(MOD_DIR)/$$i); \
	done
	@$(ECHO) done


# Target to check configuration before proceeding with install or clean
chkenv:
	@if [ "$(MOD_DIR)" = "" ]; then \
		$(ECHO) "MOD_DIR variable is not set"; \
		exit 1; \
	fi;
	@if [ "$(MOD_DIR)" = "/" ]; then \
		$(ECHO) "MOD_DIR is set to root - '/' !"; \
		exit 1; \
	fi;
	@if [ ! -x "`$(DIRNAME) $(MOD_DIR)`" ]; then \
		$(ECHO) -n "MOD_DIR parent directory "; \
		$(ECHO) "'`$(DIRNAME) $(MOD_DIR)`' does not exist"; \
		exit 1; \
	fi;
	@if [ "$(NDG_DIR)" = "" ]; then \
		$(ECHO) "NDG_DIR variable is not set"; \
		exit 1; \
	fi;
	@if [ "$(NDG_DIR)" = "/" ]; then \
		$(ECHO) "NDG_DIR is set to root - '/' !"; \
		exit 1; \
	fi;
	@if [ ! -x "`$(DIRNAME) $(NDG_DIR)`" ]; then \
		$(ECHO) -n "NDG_DIR parent directory "; \
		$(ECHO) "'`$(DIRNAME) $(NDG_DIR)`' does not exist"; \
		exit 1; \
	fi
	@if [ "$(CVSROOT)" = "" ]; then \
		$(ECHO) "CVSROOT variable is not set"; \
		exit 1; \
	fi;
