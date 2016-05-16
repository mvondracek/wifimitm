# Automation of MitM Attack on WiFi Networks
- Abstract
- Instalation
- Usage
- Bachelor Project Specification
- Reference


## Abstract
This bachelor’s thesis aims at research concerning a security of wireless networks. It delivers
a study of widely used network technologies and principles of wireless security. Analysed
technologies and security algorithms suffer weaknesses that can be exploited to perform the
MitM attack. The thesis includes an overview of available tools focused on exploiting these
individual weaknesses.

The outcome of the thesis is the *wifimitm* package and the *wifimitmcli* CLI tool, both
implemented in Python. The package provides a functionality for automated MitM attack
and can be used by other software. The *wifimitmcli* tool is capable of performing a successful
fully automated attack without any intervention from an attacking person. This research
can be used for automated penetration testing and for forensic investigation.


## Installation

```bash
make
```

The implemented automated tool depends on several other tools, which are being controlled.
*Wifimitm* has to be able to start the required tools, therefore they have to be available
on a user’s system. The *wifimitm* package itself can be automatically installed by
the package’s `setup.py`. After the installation, the implemented automated tool can
be started using its CLI named `wifimitmcli`. The rest of software dependencies can be
satisfied by installation of required tools. For convenient setup of the implemented tool,
a `Makefile` and several installation scripts and wrappers have been developed.

*MITMf* has a number of dependencies, therefore it is highly recommended to use *MITMf*
inside a virtual environment as stated in its installation guide[^MITMf_installation] .
*MITMf* could be installed using the package[^AUR_mitmf-git] available on Arch User
Repository (AUR), but unfortunately this package does not utilize the virtual environment.
An installation script `MITMf_install.sh` is able to install *MITMf*, including its dependencies.
This script also creates a virtual environment dedicated to *MITMf*. An implemented wrapper
script is used to automate activation and deactivation of the virtual environment before
and after running *MITMf*. After installation, *MITMf* can be easily run encapsulated
in its virtual environment.

*Wifiphisher* is available in form of an AUR package[^AUR_wifiphisher], but this package
is not suitable for correct installation, because currently (May 2016), it is not updated
to the changes in the repository structure of *wifiphisher*. An implemented installation script
`wifiphisher_install.sh` is able to create a dedicated virtual environment and install
*wifiphisher*. Convenient usage of *wifiphisher* installed inside its virtual environment is
achieved by a wrapper similar to the one for *MITMf*. Due to the fact that some changes
in *wifiphisher’s* source code were implemented, the installation script also applies
a software patch to the installed *wifiphisher*.

Tool *upc_keys* is implemented in the C language and therefore it is compiled during
installation. Compiled *upc_keys* and the executable wrappers for *MITMf* and *wifiphisher*,
which are described above, are linked from the `/usr/bin/` directory after the installation.
The required tools are installed by their installation scripts to the `/opt/` directory.
Installation of all the requirements can be started by `requirements_install.sh` script
or `Makefile`. A usage of implemented `Makefile`, which can be used for convenient installation,
is shown in table below.

|Command            |Description                                                     |
|-------------------|----------------------------------------------------------------|
|`make requirements`|Install requirements.                                           |
|`make install`     |Install the *wifimitm* package and the *wifimitmcli* tool.      |
|`make man`         |Install a manual page of *wifimitmcli*.                         |
|`make`, `make all` |Install requirements, the package, the tool and the manual page.|
A usage of *Makefile*

## Usage
After the installation, the CLI can be started via wifimitmcli. During *wifimitmcli’s* run,
usual output information is written to *stdout*, notifications concerning errors are written
to *stderr*. *Wifimitmcli* saves and loads attack data from the `∼/.wifimitm/` directory.
According to the fact that *wifimitmcli* is an automated tool, it does not expect any
input from a user during its progress. The user can control behaviour of *wifimitmcli* by
program arguments provided at start of *wifimitmcli*.
This way, *wifimitmcli* does not even have to be started manually by user, but it could
be a part of other scripts. Table below shows an overview of program arguments of *wifimitmcli*
tool. The synopsis of *wifimitmcli’s* arguments is specified as follows:

```bash
wifimitmcli [-h] [-v] [-ll <level> ] [-p] [-cf FILE ] <essid> <interface>
```

|Argument                                |Description                                                                     |
|----------------------------------------|--------------------------------------------------------------------------------|
|`-h`, `--help`                          |Show help message and exit.                                                     |
|`-v`, `--version`                       |Show program’s version number and exit.                                         |
|`-ll <level>`, `--logging-level <level>`|Select logging level (choices: `disabled`, `critical`, `error`, `warning`, `info`, `debug`).|
|`-p`, `--phishing`                      |Enable phishing attack if dictionary attack fails.                              |
|`-cf FILE`, `--capture-file FILE`       |Capture network traffic to provided file.                                       |
|`<ssid>`                                |Attack network with provided SSID.                                              |
|`<interface>`                           |Use provided wireless network interface for attack.                             |
Program arguments of *wifimitmcli*

As seen from the synopsis shown above, `<ssid>` and `<interface>` arguments are
mandatory to start *wifimitmcli*. In the case that provided arguments are not correct,
an appropriate error message and the synopsis is shown and the program terminates immediately
after the arguments check. For more information concerning usage of *wifimitmcli*,
a user can start the tool with `-h` or `--help` argument, which results in showing a help page.
More detailed information about *wifimitmcli* can be found on its installed manual page.
```sh
man wifimitmcli
```

The implemented Python package *wifimitm* provides a functionality to log performed
actions using Python’s *logging* [^Python_logging] module. Individual modules contained in
the *wifimitm* package posses their own logger objects. The implemented *wifimitmcli* tool
uses its logger as well. This approach makes it possible for *wifimitmcli* to control all
noted loggers. Level of logging for the loggers can be set at start of *wifimitmcli*
as a program argument.

Upon termination of the *wifimitmcli* tool, appropriate exit code
indicating the result is returned. Some of the implemented exit codes are inspired by
sysexits[^sysexits] . Exit codes of the implemented automated tool are shown in table below.

|Value|Name                    |Description                                                    |
|:---:|------------------------|---------------------------------------------------------------|
|  0  |`EX_OK`                 |Program terminated successfully.                               |
|  2  |`ARGUMENTS`             |Incorrect or missing arguments provided.                       |
| 69  |`EX_UNAVAILABLE`        |Required program or file does not exist.                       |
| 77  |`EX_NOPERM`             |Permission denied.                                             |
| 79  |`TARGET_AP_NOT_FOUND`   |Target AP was not found during scan.                           |
| 80  |`NOT_IN_ANY_DICTIONARY` |WPA/WPA2 passphrase was not found in any available dictionary. |
| 81  |`PHISHING_INCORRECT_PSK`|WPA/WPA2 passphrase obtained from phishing attack is incorrect.|
| 82  |`SUBPROCESS_ERROR`      |Failure in subprocess occured.                                 |
| 130 |`KEYBOARD_INTERRUPT`    |Program received SIGINT.                                       |
Exit codes of *wifimitmcli*


## Bachelor Project Specification
*Bachelor Project Specification/18596/2015/xvondr20*  
**Brno University of Technology - Faculty of Information Technology**  
Department of Information Systems, Academic year 2015/2016

For: **Vondráček Martin**  
Branch of study: Information Technology  
Title: **Automation of MitM Attack on WiFi Networks**
Category: Networking

### Instructions for project work
1. Study different kinds of security approaches used in wireless
   networks. Focus on known vulnerabilities of individual methods and on
   tools for exploiting these vulnerabilities.
2. Consider the possibility of impersonification of specified AP in case
   that attack on given device is not available.
3. Utilize existing tools from points 1), 2) and choose the most
   appropriate one or a set of them, which will be able to realize
   automatic attack on chosen network.
4. Implement a tool capable of such automation. This tool will be able
   to choose the most suitable attack or a sequence of them.
5. Test the solution during experiments in laboratories. Evaluate
   the success rate of implemented solution against different kinds
   of existing AP.

### Basic references
- Callegati, F., Cerroni, W. & Ramilli, M., Man-in-the-middle attack
  to the HTTPS protocol. IEEE Security and Privacy, 7(1), p.78-81. 2009.
- Dierks, T. & Rescorla, E., 2008. RFC 5246 - The transport layer
  security (TLS) protocol - Version 1.2. In *Network Working Group,
  IETF*. pp. 1-105.

### Requirements for the first semester
Items 1, 2 a 3.

**Detailed formal specifications can be found at
[http://www.fit.vutbr.cz/info/szz/](
http://www.fit.vutbr.cz/info/szz/).**

*The Bachelor Thesis must define its purpose, describe a current state
of the art, introduce the theoretical and technical background relevant
to the problems solved, and specify what parts have been used from
earlier projects or have been taken over from other sources.*

*Each student will hand-in printed as well as electronic versions
of the technical report, an electronic version of the complete program
documentation, program source files, and a functional hardware
prototype sample if desired. The information in electronic form will be
stored on a standard non-rewritable medium (CD-R, DVD-R, etc.) in
formats common at the FIT. In order to allow regular handling,
the medium will be securely attached to the printed report.*

Supervisor: **Pluskal Jan, Ing.**, DIFS FIT BUT  
Beginning of work: November 1, 2015  
Date of delivery: May 18, 2016


## Reference
VONDRÁČEK, Martin. *Automation of MitM Attack on WiFi Networks*. Brno, 2016. Bachelor’s thesis.
Brno University of Technology, Faculty of Information Technology. Supervisor Pluskal Jan.


[^MITMf_installation]: URL: https://github.com/byt3bl33d3r/MITMf/wiki/Installation
[^AUR_mitmf-git]: URL: https://aur.archlinux.org/packages/mitmf-git/
[^AUR_wifiphisher]: URL: https://aur.archlinux.org/packages/wifiphisher/
[^Python_logging]: URL: https://docs.python.org/3/library/logging.html
[^sysexits]: URL: http://linux.die.net/include/sysexits.h


*[AP]: Access Point
*[STA]: Station
*[WLAN]: Wireless Local Area Network
*[HTTPS]: Hypertext Transfer Protocol Secure
*[MITMf]: Framework for Man-In-The-Middle attacks
*[CLI]: Command Line Interface
*[AUR]: Arch User Repository
*[stdin]: Standard input stream
*[stdout]: Standard output stream
*[stderr]: Standard error stream
*[SSID]: Service Set Identifier
*[WPA]: Wi-Fi Protected Access
*[WPA2]: Wi-Fi Protected Access II
*[ESSID]: Extended Service Set Identifier

