#! /bin/bash
#
# Set-up script for NDG security software
#
# Run this script to initialise the environment for
# NDG security
#
# NERC Data Grid Project
#
# P J Kershaw 21/10/05
#
# Copyright (C) 2005 CCLRC & NERC
#
# This software may be distributed under the terms of the Q Public License,
# version 1.0 or later.
#
# $Id$

# NDG Installation directory
export NDG_DIR=<NDG location>


# NDG bin directory
if [ ! `echo ${PATH} | grep "${NDG_DIR}/bin"` ]; then

    export PATH=${NDG_DIR}/bin:$PATH
fi


# NDG shared libraries - set path here or alternatively use ldconfig $NDG_DIR/lib from
# the command line to link the NDG shared libraries.
#if [ ! `echo ${LD_LIBRARY_PATH} | grep "${NDG_DIR}/lib"` ]; then
#
#    export LD_LIBRARY_PATH=${NDG_DIR}/lib:$LD_LIBRARY_PATH
#fi


# NDG Custom Python installation
if [ ! `echo ${PATH} | grep "${NDG_DIR}/<Python location>"` ]; then

    export PATH=${NDG_DIR}/<Python location>:$PATH
fi


# Override default locations for properties files.
#
# e.g. default Attribute Authority location is 
# $NDG_DIR/conf/attAuthorityProperties.xml
#
# Session Manager:
# $NDG_DIR/conf/sessionMgrProperties.xml
#
# Certificate Authority:
# $NDG_DIR/conf/simpleCAProperties.xml
#
#export NDGSEC_AA_PROPFILEPATH=
#export NDGSEC_SM_PROPFILEPATH=
#export NDGSEC_CA_PROPFILEPATH=


# Globus Toolkit and MyProxy Server
export GLOBUS_LOCATION=<Globus location>
export GPT_LOCATION=${GLOBUS_LOCATION}
export GRID_SECURITY_DIR=${GLOBUS_LOCATION}/etc

. ${GLOBUS_LOCATION}/etc/globus-user-env.sh

export MYPROXY_SERVER=<hostname>

# Set DN explicitly to ensure match with server certificate
#export MYPROXY_SERVER_DN="<hostcert DN with '/' delimiters>"


if [ ! `echo ${PATH} | grep "${GLOBUS_LOCATION}/bin"` ]; then

    export PATH=${PATH}:${GLOBUS_LOCATION}/bin
fi


# MySQL or other database
if [ ! `echo ${PATH} | grep "<db location>"` ]; then

    export PATH=<db location>:$PATH
fi
