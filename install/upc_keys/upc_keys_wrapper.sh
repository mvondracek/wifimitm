#!/usr/bin/env bash
##
## upc_keys wrapper https://haxx.in/upc-wifi/
##
## Automation of MitM Attack on WiFi Networks
## Bachelor's Thesis UIFS FIT VUT
## Martin Vondracek
## 2016
##

## Error exit codes
EX_UNAVAILABLE=69

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR=${SCRIPT_DIR}
LIBS_DIR=${PROJECT_DIR}/libs
PROGNAME=$(basename $0)


${LIBS_DIR}/upc_keys/upc_keys $* | grep "  -> WPA2 phrase for " | sed "s/^  -> WPA2 phrase for \S* = '\(.*\)'$/\1/"
UPC_KEYS_EXITCODE=${PIPESTATUS[0]}

exit ${UPC_KEYS_EXITCODE}
