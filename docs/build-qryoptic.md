# Qryoptic: Build, Initialize, and Test

This guide walks you through setting up, building, and initializing the `qryoptic` PKCS#11 module.

<details open="open">
<summary>Table of Contents</summary>

- [Qryoptic: Build, Initialize, and Test](#qryoptic-build-initialize-and-test)
  - [Prerequisites](#prerequisites)
  - [Build](#build)
  - [Module Initialization](#module-initialization)
  - [Next Steps: Set Up Firefox and Test the Module](#next-steps-set-up-firefox-and-test-the-module)

</details>

---

## Prerequisites

> [!IMPORTANT]️
> Most dependencies are already defined in `Cargo.toml` and will be handled automatically by Cargo during the build process.

Some of the dependencies are crates which themselves depend on system tools and libraries.

Before building the project, make sure you have the following system packages installed:

- `libsqlite3-dev`: Used for managing the token store with SQLite.

  ```sh
  sudo apt install libsqlite3-dev
  ```

  > However, if you encounter issues related to `libclang-dev`, run the following command:

  ```sh
  sudo apt install libclang-dev
  ```

- `pkcs11-tool`: A tool from the OpenSC suite, used to initialize and interact with the PKCS#11 module.

  ```sh
  sudo apt install opensc
  ```

## Build

Start by cloning the repository and after that move to the cloned folder:

```sh
git clone git@github.com:qubip/qryoptic.git
cd qryoptic
```

Once you clone the repository, you can build the project using:

```sh
cargo build
```

To make sure everything is working correctly, you can run the internal test suite:

```sh
cargo test
```

> [!NOTE]
> Test coverage for the Rust-only logic is still in progress, so some areas may not be fully tested yet, and some tests unrelated to the PQC transition are currently known to fail.
>
> We're actively working to improve this.

## Module Initialization

Before using the module, you’ll need to create and initialize a file-based token store, which will be used to store and maintain the module’s internal state.

The token file is managed using SQLite.

Run the following commands to create the default directory and initialize an empty token file in it.
This will be properly initialized in the next step.

```sh
mkdir -p ~/.local/share/qryoptic
touch ~/.local/share/qryoptic/token.sql
```

> [!IMPORTANT]
> By default, the `qryoptic` module will look for `token.sql` in `~/.local/share/qryoptic`,
> but this path is influenced by some environment variables, including those tuning XDG preferences.

Once the token file is created, you can initialize the module by running the following command:

```sh
pkcs11-tool --module ./target/debug/libqryoptic_pkcs11.so --init-token --slot 0 --label "qryoptic_module" --so-pin 1234 --init-pin --pin 1234
```

If everything works correctly, you should see:

```txt
Token successfully initialized
User PIN successfully initialized
```

While not strictly part of initialization, you can also explore more information using:

```sh
pkcs11-tool --help
```

For example:

```sh
pkcs11-tool --module ./target/debug/libqryoptic_pkcs11.so --show-info
```

## Next Steps: Set Up Firefox and Test the Module

Now that your module is ready to use, the next step is to integrate it into a Firefox environment that supports external PKCS#11 modules.

You have two possible options to proceed:

- [Build Firefox from source](./build-firefox-from-source.md): Ideal if you are looking for full control and debugging options.
- [Flatpak-based Firefox image](./installing-flatpak-firefox.md): Quicker to set up and testing.

Once Firefox is set up, follow the [testing guide](./test-with-firefox.md) to load the `qryoptic` module and test it.

---
