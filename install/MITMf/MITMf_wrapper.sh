#!/usr/bin/env bash
##
## MITMf wrapper
##
## Automation of MitM Attack on WiFi Networks
## Bachelor's Thesis UIFS FIT VUT
## Martin Vondracek
## 2016
##


INSTALL_NAME="MITMf"


## Error exit codes
EX_UNAVAILABLE=69

INSTALL_DIR="/opt/${INSTALL_NAME}"
PROGNAME=$(basename $0)

## Print error message and exit
##   $1 error code
##   $2 error description
function error_exit
{
	echo -e "[\e[31mFAIL\e[0m] ${PROGNAME}: ${2:-"Unknown Error"}" >&2
	exit ${1:-$EX_UNAVAILABLE}
}


source ${INSTALL_DIR}/ve_${INSTALL_NAME}/bin/activate || error_exit $? "activate virtualenv"
cd ${INSTALL_DIR}/${INSTALL_NAME} || error_exit $? "cd to ${INSTALL_NAME} directory"

python mitmf.py $*
EXITCODE=$?

deactivate || error_exit $? "deactivate virtualenv"

exit ${EXITCODE}
