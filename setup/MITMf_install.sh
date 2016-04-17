#!/bin/bash
##
## Install MITMf and setup its virtualenv
##
## Automatization of MitM Attack on WiFi Networks
## Bachelor's Thesis UIFS FIT VUT
## Martin Vondracek
## 2016
##

# TODO pacman -S python2-setuptools libnetfilter_queue libpcap libjpeg-turbo capstone


## Error exit codes
ERR_TASK=101

PROJECT_DIR=$(pwd)/..
LIBS_DIR=${PROJECT_DIR}/libs
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


announce_task "MITMf install"


TASK="Set MITMf wrapper as executable"
announce_task "${TASK}"
chmod +x ${PROJECT_DIR}/MITMf_wrapper.sh
check_task_result $? "${TASK}"

read
TASK="Make libs dir"
announce_task "${TASK}"
mkdir --parents ${LIBS_DIR}
check_task_result $? "${TASK}"

TASK="cd ${LIBS_DIR}"
announce_task "${TASK}"
cd ${LIBS_DIR}
check_task_result $? "${TASK}"


TASK="Create ve_MITMf virtualenv"
announce_task "${TASK}"
virtualenv ve_MITMf -p /usr/bin/python2.7
check_task_result $? "${TASK}"


TASK="Activate ve_MITMf virtualenv"
announce_task "${TASK}"
source ${LIBS_DIR}/ve_MITMf/bin/activate
check_task_result $? "${TASK}"


TASK="Clone the MITMf repository"
announce_task "${TASK}"
git clone https://github.com/byt3bl33d3r/MITMf
check_task_result $? "${TASK}"


TASK="Initialize and clone the repository's submodules"
announce_task "${TASK}"
cd MITMf && git submodule init && git submodule update --recursive
check_task_result $? "${TASK}"


TASK="Install the dependencies"
announce_task "${TASK}"
pip install -r requirements.txt
check_task_result $? "${TASK}"


TASK="cd ${PROJECT_DIR}"
announce_task "${TASK}"
cd ${PROJECT_DIR}
check_task_result $? "${TASK}"


TASK="Deactivate ve_MITMf virtualenv"
announce_task "${TASK}"
deactivate
check_task_result $? "${TASK}"


check_task_result true "MITMf install"
exit 0
