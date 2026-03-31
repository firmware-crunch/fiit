
# Fiit - Firmware Instrumentation and Introspection Tools

[![Coverage badge](https://raw.githubusercontent.com/firmware-crunch/fiit/fiit-py-cov/badge.svg)](https://htmlpreview.github.io/?https://github.com/firmware-crunch/fiit/blob/fiit-py-cov/htmlcov/index.html)
[![Tests badge](https://github.com/firmware-crunch/fiit/actions/workflows/tests.yaml/badge.svg)](https://github.com/firmware-crunch/fiit/actions/workflows/tests.yaml)
[![Build badge](https://github.com/firmware-crunch/fiit/actions/workflows/build.yaml/badge.svg)](https://github.com/firmware-crunch/fiit/actions/workflows/build.yaml)
[![PyPI version](https://badge.fury.io/py/fiit-py.svg)](https://pypi.org/project/fiit-py/)

Fiit aims to provide a toolbox for firmware instrumentation and in-depth dynamic analysis, in emulated or physical environment.
This project targets exotic CPU architectures and bare-metal or real-time operating system that requires minimally intrusive instrumentation.
The library provides a set of python interfaces and a high-level framework interface, which enable the creation of custom runtime environments with advanced firmware introspection capabilities at the processor, peripheral and software levels.

## Installation

Fiit is available on PyPI:

```text
$ pip install fiit-py
```

## Framework Features

The following plugins are available via YAML file configuration:

- Machine and devices interface:
    * Designed for multiple ISA emulation backend (Unicorn, ...).
    * Designed for complex hardware scenario with multiples processors.
    * Devices available: PL190.

- MMIO Trace:
    * Log mmio access.
    * Specify CMSIS-SVD specification for detailed annotation.
    * Statistical analysis with graphical representations.

- MMIO Debugger:
    * Debug mmio access step by step, a king of data breakpoint but customised for mmio.
    * Specify CMSIS-SVD specification for detailed annotation.
    * Useful for firmware rehosting.

- Hooking Engine:
    * Define function location via config file.
    * Handle C data type and function definition via regular C header.
    * Define various hooking strategies: pre hook, post hook, replace hook.
    * Access C function arguments from hook via a custom ctypes Python interface.
    * Modify C function arguments and return value from hook.
    * Call C function from hook.
    * Calling convention available: AAPCS32.

- Function Trace:
    * Log function.
    * Specify C header for C function definition and C data type handling.
    * FreeRTOS task filter extension via `pxCurrentTCB` location definition.

- C Data Type Mapping:
    * Define C data types definition via config file or at runtime.
    * Access C Data types from everywhere in the Fiit runtime.

- Debugger:
    * Debugger API inspired from GDB.
    * Out-of-band debugging, zero trace in memory.

- Shell:
    * Full access to plugins and Fiit runtime.
    * Local IPython shell.
    * Remote Jupyter Terminal with multiuser support.
    * Access to a command line interface for: Machine, MMIO Trace, MMIO Debugger, C Data Type Mapping and Debugger.


Many other plugins are not yet released.
