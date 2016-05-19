#!/usr/bin/env bash
##
## Install man_page
##
## Automation of MitM Attack on WiFi Networks
## Bachelor's Thesis UIFS FIT VUT
## Martin Vondracek
## 2016
##


INSTALL_NAME="man page wifimitmcli(1)"


## Error exit codes
ERR_TASK=101

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
INSTALL_DIR="/usr/local/share/man/man1"
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
    echo -e "[\e[31mFAIL\e[0m] ${PROGNAME}: ${INSTALL_NAME} install" >&2
    exit $(expr 128 + ${1?})
}


trap "stop 1" SIGHUP
trap "stop 2" SIGINT
trap "stop 15" SIGTERM


function main()
{
    announce_task "${INSTALL_NAME} install"


    TASK="Make man page directory"
    announce_task "${TASK}"    
    mkdir --parents ${INSTALL_DIR}
    check_task_result $? "${TASK}"


    TASK="gzip man page"
    announce_task "${TASK}"
    gzip --keep ${SCRIPT_DIR}/wifimitmcli.1 
    check_task_result $? "${TASK}"


    TASK="copy man page"
    announce_task "${TASK}"
    cp --interactive ${SCRIPT_DIR}/wifimitmcli.1.gz ${INSTALL_DIR}/wifimitmcli.1.gz
    check_task_result $? "${TASK}"


    TASK="clean"
    announce_task "${TASK}"
    rm ${SCRIPT_DIR}/wifimitmcli.1.gz
    check_task_result $? "${TASK}"


    TASK="mandb"
    announce_task "${TASK}"
    mandb --no-purge
    check_task_result $? "${TASK}"


    check_task_result true "${INSTALL_NAME} install"
    exit 0
}

main
