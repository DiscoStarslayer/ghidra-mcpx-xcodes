MCPX XCodes Ghidra Plugin
----
This repository contains a plugin for Ghidra that enables decompilation support for the MCPX X-Codes in Ghidra

## Building
This project requires Gradle 7+ and OpenJDK 11. It has only been tested on Ghidra 10.2.2.
```shell
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension
```

## Installing
Builds are distributed on the [RELEASES](https://github.com/DiscoStarslayer/ghidra-mcpx-xcodes/releases) page. These can be installed
directly into Ghidra by selecting `File -> Install Extensions` from the main Ghidra UI.

The installation includes support for the XCode instruction set, as well as a file loader that will detect original xbox firmware files
and automatically setup the memory space for the firmware.
