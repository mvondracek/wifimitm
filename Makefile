##
## Makefile
##
## Automation of MitM Attack on WiFi Networks
## Bachelor's Thesis UIFS FIT VUT
## Martin Vondracek
## 2016
##
## Usage:
##   make all
##     Install requirements, the package, the tool and the manual page.
##
##   make requirements
##     Install requirements.
##
##   make man
##     Install a manual page of wifimitmcli.
##
##   make install
##     Install the wifimitm package and the wifimitmcli tool.


SHELL = /bin/sh


.PHONY: all requirements install man

all: requirements install man

requirements:
	sh ./install/requirements_install.sh

install:
	pip install .

man:
	sh ./install/man_page/man_page_install.sh

