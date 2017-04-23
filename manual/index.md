[Homepage](../index.md)

---

- [Instalation](#installation)
  - [Hardware requirements](#hardware-requirements)
- [Usage](#usage)

---

### Installation
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

***MITMf (Framework for Man-In-The-Middle attacks)*** has a number of dependencies,
therefore it is highly recommended to use *MITMf*
inside a virtual environment as stated in its installation guide[(^MITMf_installation)] .
*MITMf* could be installed using the package[(^AUR_mitmf-git)] available on Arch User
Repository (AUR), but unfortunately this package does not utilize the virtual environment.
An installation script `MITMf_install.sh` is able to install *MITMf*, including its dependencies.
This script also creates a virtual environment dedicated to *MITMf*. An implemented wrapper
script is used to automate activation and deactivation of the virtual environment before
and after running *MITMf*. After installation, *MITMf* can be easily run encapsulated
in its virtual environment.

***Wifiphisher*** is available in form of an AUR package[(^AUR_wifiphisher)], but this package
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
or `Makefile`. A usage of implemented `Makefile`, which can be used for a convenient installation,
is shown in table below.

Table: A usage of *Makefile*

|Command            |Description                                                     |
|-------------------|----------------------------------------------------------------|
|`make requirements`|Install requirements.                                           |
|`make install`     |Install the *wifimitm* package and the *wifimitmcli* tool.      |
|`make man`         |Install a manual page of *wifimitmcli*.                         |
|`make`, `make all` |Install requirements, the package, the tool and the manual page.|


#### Hardware requirements
Due to the nature of specific steps of the attack, a special hardware equipment is required.
During the scanning and capturing of network traffic without being connected to the network,
an attacking device needs a wireless network interface in monitor mode. For sending special
forged packets, the wireless network interface also needs to be capable of packet injection.
In order to be able to perform a phishing attack, a second wireless interface capable
of master ([AP]) mode has to be available.

The user can check whether his hardware is capable of packet injection using the
*aireplay-ng* tool executed as `aireplay-ng --test <replay interface>`. Managing monitor mode
of interface is possible with the *airmon-ng* tool.


### Usage
After the installation, the CLI can be started via wifimitmcli. During *wifimitmcli’s* run,
usual output information is written to *stdout*, notifications concerning errors are written
to *stderr*. *Wifimitmcli* saves and loads attack data from the `∼/.wifimitm/` directory.
According to the fact that *wifimitmcli* is an automated tool, it does not expect any
input from a user during its progress. The&nbsp;user can control behaviour of&nbsp;*wifimitmcli* by
program arguments provided at start of&nbsp;*wifimitmcli*.
This way, *wifimitmcli* does not even have to be started manually by user, but it could
be a part of&nbsp;other scripts.

For information concerning usage of *wifimitmcli*, a&nbsp;user can start the tool
with `-h` or `--help` argument, which results in showing a help page.
More detailed information about *wifimitmcli* can be found on its installed manual page.

```sh
wifimitmcli --help
```

```sh
man wifimitmcli
```

Table below shows an overview of&nbsp;program arguments of&nbsp;*wifimitmcli*
tool. The&nbsp;synopsis of *wifimitmcli’s* arguments is specified as follows:

```
wifimitmcli [-h] [-v] [-ll <level> ] [-p] [-cf FILE ] <ssid> <interface>
```

Table: Program arguments of *wifimitmcli*

|Argument                                |Description                                                                     |
|----------------------------------------|--------------------------------------------------------------------------------|
|`-h`, `--help`                          |Show help message and exit.                                                     |
|`-v`, `--version`                       |Show program’s version number and exit.                                         |
|`-ll <level>`, `--logging-level <level>`|Select logging level (choices: `disabled`, `critical`, `error`, `warning`, `info`, `debug`).|
|`-p`, `--phishing`                      |Enable phishing attack if dictionary attack fails.                              |
|`-cf FILE`, `--capture-file FILE`       |Capture network traffic to provided file.                                       |
|`<ssid>`                                |Attack network with provided SSID.                                              |
|`<interface>`                           |Use provided wireless network interface for attack.                             |

As seen from the synopsis shown above, `<ssid>` and `<interface>` arguments are
mandatory to start *wifimitmcli*. In the case that provided arguments are not correct,
an appropriate error message and the synopsis is shown and the program terminates immediately
after the arguments check. 

The implemented Python package *wifimitm* provides a functionality to log performed
actions using Python’s *logging* [(^Python_logging)] module. Individual modules contained in
the *wifimitm* package posses their own logger objects. The implemented *wifimitmcli* tool
uses its logger as well. This approach makes it possible for *wifimitmcli* to control all
noted loggers. Level of logging for the loggers can be set at start of *wifimitmcli*
as a program argument.

Upon termination of the *wifimitmcli* tool, appropriate exit code
indicating the result is returned. Some of the implemented exit codes are inspired by
sysexits[(^sysexits)] . Exit codes of the implemented automated tool are shown in table below.

Table: Exit codes of *wifimitmcli*

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





[(^MITMf_installation)]: (https://github.com/byt3bl33d3r/MITMf/wiki/Installation)

[(^AUR_mitmf-git)]: (https://aur.archlinux.org/packages/mitmf-git/)

[(^AUR_wifiphisher)]: (https://aur.archlinux.org/packages/wifiphisher/)

[(^Python_logging)]: (https://docs.python.org/3/library/logging.html)

[(^sysexits)]: (http://linux.die.net/include/sysexits.h)
