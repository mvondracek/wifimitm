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
##     make requirements
##     make install
##     make man
##
##   make requirements
##     install requirements
##
##   make man
##     install the wifimitmcli(1) manual page
##
##   make install
##     install the wifimitm package and the wifimitmcli tool

.PHONY: all requirements install man

all: requirements install man

requirements:
	sh ./install/requirements_install.sh

install:
	python ./setup.py install

man:
	sh ./install/man_page/man_page_install.sh

