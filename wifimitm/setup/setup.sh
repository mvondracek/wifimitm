#!/bin/bash
##
## setup
##
## Automatization of MitM Attack on WiFi Networks
## Bachelor's Thesis UIFS FIT VUT
## Martin Vondracek
## 2016
##

# TODO airodump-ng-oui-update
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "config simlinks"

TASK="NetworkManager.conf"
sudo ln --symbolic --force \
"${SCRIPT_DIR}/etc/NetworkManager/NetworkManager.conf" \
      /etc/NetworkManager/NetworkManager.conf

if [[ $? -eq 0 ]]; then
	echo -e "\e[32m[ OK ]\e[0m $TASK"
else		
	echo -e "\e[31m[FAIL]\e[0m $TASK" >&2
	exit 1
fi

