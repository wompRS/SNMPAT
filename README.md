# SNMPAT

## Description
SNMPAT (SNMP Auditing Tool) is a project that provides a set of tools for SNMP (Simple Network Management Protocol) monitoring and management. It automates the auditing of your local network's SNMP fingerprint by testing a variety of community strings, both vulnerable or weak. It then generates an easy-to-read document that helps you remediate any identified issues.

## Features
- SNMPAT supports SNMPv1, SNMPv2c, and SNMPv3 protocols.
- It allows you to perform SNMP GET, GETNEXT, GETBULK, and SET operations.
- SNMPAT provides a command-line interface for easy integration into scripts and automation workflows.
- It supports both IPv4 and IPv6 addresses for SNMP communication.
- The scanner lets you supply custom SNMP community strings or use a built-in default list.

## Usage

Run the script and follow the prompts to enter target subnets/IPs and SNMP community strings:

```bash
./SNMPAT.sh
```

During execution you can build the SNMP community string list by combining any of the following sources:

- Add the built-in defaults with one menu selection.
- Enter additional strings directly (comma or space separated); duplicate and blank values are ignored automatically.
- Load strings from a text or CSV file, where values can be separated by commas or whitespace across multiple lines.

You can review the growing list after each addition and only proceed once you are satisfied, ensuring the scan always runs with a clean, deduplicated set of community strings.

When you are ready to supply targets, enter subnets, IPs, or file paths in any order. Use the `done` keyword to review a summary of
the current selections; the script highlights any IPs already covered by one of the subnets so you know exactly what will be scanned
before the tool continues.

### Testing

The repository includes a lightweight smoke test that exercises the interactive prompts with mocked `onesixtyone` and `dig` binaries. Run it from the project root with:

```bash
tests/run_tests.sh
./snmpat.sh
```

## Dependencies
SNMPAT has the following dependencies:

- **onesixtyone**: This tool is used for SNMP community string scanning. To install it, you can follow these steps:
  1. Clone the onesixtyone repository:
      ```shell
      git clone https://github.com/trailofbits/onesixtyone.git
      ```
  2. Build and install onesixtyone:
      ```shell
      cd onesixtyone
      make
      sudo make install
      ```

- **python3**: SNMPAT is written in Python and requires Python 3. To install it, you can follow these steps:
  1. Check if Python 3 is already installed by running the following command:
      ```shell
      python3 --version
      ```
  2. If Python 3 is not installed, you can download and install it from the official Python website: [https://www.python.org/downloads/](https://www.python.org/downloads/)

Make sure to install these dependencies before using SNMPAT.


## Installation
1. Clone the SNMPAT repository:
    ```shell
    git clone https://github.com/womprs/SNMPAT.git
    ```

## Credits
SNMPAT is developed and maintained by [womprs](https://github.com/womprs).
