#
# Makefile to generate epydoc documentation for the MyProxy Client Package
#
# NERC Data Grid Project
#
# @author P J Kershaw 15/12/08
#

# @copyright: (C) 2008 CCLRC & NERC
#
# @license: This software may be distributed under the terms of the Q Public
# License, version 1.0 or later.
#
# $Id$

# Generate HTML from embedded epydoc text in source code.
EPYDOC=epydoc
EPYDOC_OUTDIR=.
EPYDOC_NAME='MyProxy Client'
EPYDOC_LOGFILE=epydoc.log
EPYDOC_FRAMES_OPT=--no-frames
epydoc:
	${EPYDOC} ../myproxy -o ${EPYDOC_OUTDIR} --name ${EPYDOC_NAME} \
	${EPYDOC_FRAMES_OPT} --include-log --graph=all -v > ${EPYDOC_LOGFILE}
	
clean:
	rm -f *.txt *.html *.gif