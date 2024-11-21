# QUBIP Loadable Module

This is a PKCS#11 software token implemented in Rust for the QUBIP project. It is a fork of the Kryoptic project, with the primary distinction being the added capability to build the project as a Rust-only version.

The objective of this project is to develop a framework for integrating Post-Quantum Cryptography (PQC) functionality into the Network Security Services (NSS).

# Dependencies

Most of the dependencies are listed in the `cargo.toml` and will be installed through Cargo.

To build the project you still need to install:

sqlite:

    $ sudo apt install sqlite3

# Setup

This is for legacy reasons concerning the Kryoptic project, but still
needed to build our project. The openssl dependencies will not be included in the `pure-rust` build target.

First after cloning, we need to pull and update openssl submodule:

    $ git submodule init
    $ git submodule update

Build the rust project:

    $ cargo build --features pure-rust

# Tests

The tests still need some improvement to fully match the pure-rust implementation. We can still run them.

To run test, run the check command:

    $ cargo test --features pure-rust

# Validation

The validation of the software token is done using the `pkcs11-tool` a tool part of the `OpenSC` project that can be used to manage keys on a PKCS#11 software token.

Install the tool by:

    $ sudo apt install pkcs11-tool

### Environment setup for the loadable module
This is done in the root of the project. We setup an empty database sqlite file for the token.

Set the KRYOPTIC_CONF environment variable by:

    $ touch <project-root>/token.sql
    $ export KRYOPTIC_CONF=<project-root>/token.sql

### Validation of the loadable module functionality

Initialize the loadable module with `pkcs11-tool` by:

    $ pkcs11-tool --module <project-root>/target/debug/libkryoptic_pkcs11.so --init-token --slot 0 --label "QUBIP_Module" --so-pin "1234"

You should see a `Token successfully initialized` message in your terminal.

Not part of validation but you can see other information using the tool by:

    $ pkcs11-tool --help

For example:

    $ pkcs11-tool --module <project-root>/target/debug/libkryoptic_pkcs11.so --show-info