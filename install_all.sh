#!/usr/bin/env bash
##
## Install all requirements
##
## Automation of MitM Attack on WiFi Networks
## Bachelor's Thesis UIFS FIT VUT
## Martin Vondracek
## 2016
##


## Error exit codes
ERR_TASK=101

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROGNAME=$(basename $0)

## Check install task result
##   $1 exitcode of the task
##   $2 task description
function check_task_result()
{
	EXITCODE=${1?}
    TASK="${2?}"

	if [[ ${EXITCODE} -eq 0 ]]; then
        echo -e "[\e[32m OK \e[0m] ${PROGNAME}: ${TASK}"
    else
        echo -e "[\e[31mFAIL\e[0m] ${PROGNAME}: ${TASK}" >&2
        exit ${ERR_TASK}
    fi
}

## Announce start of install task
##   $1 task description
function announce_task()
{
	TASK="${1?}"

    echo -e "[ DO ] ${PROGNAME}: ${TASK}"
}

## Stop after receiving signal
##   $1 signal number
function stop()
{
    echo -e "[\e[31mFAIL\e[0m] ${PROGNAME}: MITMf install" >&2
    exit $(expr 128 + ${1?})
}


trap "stop 1" SIGHUP
trap "stop 2" SIGINT
trap "stop 15" SIGTERM


function main()
{
    announce_task "install"


    TASK="MITMf"
    announce_task "${TASK}"
    ${SCRIPT_DIR}/install/MITMf_install.sh
    check_task_result $? "${TASK}"


    TASK="MITMf"
    announce_task "${TASK}"
    ${SCRIPT_DIR}/install/upc_keys_install.sh
    check_task_result $? "${TASK}"


    check_task_result true "install"
    exit 0
}

main