#!/bin/bash
#
# Client script for web service interface to MyProxy get-trustroots based on 
# curl and base64 commands.  Get trust roots retrieves the CA certificate 
# issuer(s) of the MyProxy server's SSL certificate
#
# @author P J Kershaw 07/06/2010
#
# @copyright: (C) 2010 STFC
#
# @license: BSD - See top-level LICENCE file for licence details
#
# $Id$
cmdname=$(basename $0)
cmdline_opt=`getopt -o hU:bc: --long help,uri:,bootstrap,ca-directory: -n "$cmdname" -- "$@"`

usage="Usage: $cmdname [-h][-U get trust roots URI][-b][-c CA directory]\n
\n
   Options\n
       -h | --help\t\t\t\tDisplays usage and quits.\n
       -U | --uri <uri>\t\t\tMyProxy web service URI\n
       -b | --bootstrap\t\t\tbootstrap trust in the MyProxy Server\n
       -c | --ca-directory <directory path>\tDirectory to store the trusted\n
       \t\t\t\t\tCA (Certificate Authority) certificates.  Defaults to\n 
       \t\t\t\t\t${HOME}/.globus/certificates or\n
       \t\t\t\t\t/etc/grid-security/certificates if running as root.\n
"

if [ $? != 0 ] ; then
    echo -e $usage >&2 ;
    exit 1 ;
fi

eval set -- "$cmdline_opt"

while true ; do
    case "$1" in
        -h|--help) echo -e $usage ; exit 0 ;;
        -U|--uri) uri=$2 ; shift 2 ;;
        -b|--bootstrap) bootstrap=1 ; shift 1 ;;
        -c|--ca-directory) cadir=$2 ; shift 2 ;;
         --) shift ; break ;;
        *) echo "Error parsing command line" ; exit 1 ;;
    esac
done

if [ -z $uri ]; then
    echo -e Give the URI for the MyProxy web service get trust roots request;
    echo -e $usage >&2 ;
    exit 1;
fi

# Set-up destination trust root directory
if [ $cadir ]; then
    if [ ! -d $cadir ]; then
        mkdir -p $cadir
    fi
    
elif [ ${X509_CERT_DIR} ]; then
    cadir=${X509_CERT_DIR}
    
elif [ "$LOGNAME" = "root" ]; then
    cadir=/etc/grid-security/certificates
    
    # Check path exists and if not make it
    if [ ! -d "/etc/grid-security" ]; then
        mkdir /etc/grid-security
    fi
       
    if [ ! -d "/etc/grid-security/certificates" ]; then
        mkdir /etc/grid-security/certificates
    fi
else
    cadir=${HOME}/.globus/certificates
    
    # Check path exists and if not make it
    if [ ! -d "${HOME}/.globus" ]; then
        mkdir ${HOME}/.globus
    fi
    
    if [ ! -d "${HOME}/.globus/certificates" ]; then
        mkdir ${HOME}/.globus/certificates
    fi
fi

# Set peer authentication based on bootstrap command line setting
if [ -z $bootstrap ]; then 
    ca_arg="--ca-directory $cadir"
else
    echo Bootstrapping MyProxy server root of trust.
    ca_arg="--no-check-certificate"
fi

# Make a temporary file for error output
error_output_filepath="/tmp/$UID-$RANDOM.csr"

# Post request to MyProxy web service
response=$(wget $uri  --secure-protocol SSLv3 $ca_arg -t 1 -O - 2> $error_output_filepath)

# Extract error output and clean up
error_output=$(cat $error_output_filepath)
rm -f $error_output_filepath

# Pull out the response code from the error output
wget_statcode_line="HTTP request sent, awaiting response..."
responsecode=$(echo "$error_output"|grep "$wget_statcode_line"|awk '{print $6}')
if [ "$responsecode" != "200" ]; then
    echo "MyProxy server returned error code $responsecode:" >&2
    echo "$responsemsg" >&2
    exit 1
fi

# Process response
entries=$(echo $response|awk '{print $0}')
for i in $entries; do
    filename=${i%%=*}
    filecontent="$(echo ${i#*=}|sed -e "s/.\{65\}/&\n/g"|openssl enc -d -base64)"
    echo "$filecontent" > $cadir/$filename
done

echo Trust roots have been installed in $cadir.
