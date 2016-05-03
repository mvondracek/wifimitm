#!/usr/bin/env bash
##
## MITMf wrapper
##
## Automation of MitM Attack on WiFi Networks
## Bachelor's Thesis UIFS FIT VUT
## Martin Vondracek
## 2016
##

## Error exit codes
EX_UNAVAILABLE=69

MITMF_DIR="/opt/MITMf"
PROGNAME=$(basename $0)

## Print error message and exit
##   $1 error code
##   $2 error description
function error_exit
{
	echo -e "[\e[31mFAIL\e[0m] ${PROGNAME}: ${2:-"Unknown Error"}" >&2
	exit ${1:-$EX_UNAVAILABLE}
}


source ${MITMF_DIR}/ve_MITMf/bin/activate || error_exit $? "activate virtualenv"
cd ${MITMF_DIR}/MITMf || error_exit $? "cd to MITMf directory"

python mitmf.py $*
MITMF_EXITCODE=$?

deactivate || error_exit $? "deactivate virtualenv"

exit ${MITMF_EXITCODE}
