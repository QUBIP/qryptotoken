# Build Firefox from Source

<details open="open">
<summary>Table of Contents</summary>

- [Build Firefox from Source](#build-firefox-from-source)
  - [About](#about)
    - [Testing](#testing)
  - [Getting Started](#getting-started)
    - [System Requirements](#system-requirements)
    - [Bootstrapping the Environment](#bootstrapping-the-environment)
    - [Cloning the Source](#cloning-the-source)
  - [Building Firefox](#building-firefox)
  - [Running Firefox](#running-firefox)
  - [Error Logging](#error-logging)
  - [Debugging](#debugging)
  - [Misc](#misc)
    - [Editor Integration](#editor-integration)

</details>

---

## About

This guide outlines the steps for building a local copy of **Mozilla Firefox**, tailored specifically for use with the `qryoptic` PKCS#11 module, developed as part of the [QUBIP](https://www.qubip.eu) project.

Mozilla's official documentation is extensive and well-maintained. We **highly recommend** reviewing it for full context:

- 📚 [Firefox Source Docs](https://firefox-source-docs.mozilla.org/)
- ⚡ [Contributor Quick Reference](https://firefox-source-docs.mozilla.org/contributing/contribution_quickref.html)

This guide supplements that documentation with a focused, minimal workflow to get you up and running **quickly** using `git` instead of Mercurial.

### Testing

_Once you’ve finished setting up Firefox using this guide and have built the `qryoptic` module (see: [README.md](/README.md)), you’re ready to **test** its integration with Firefox. See: [`test-with-firefox.md`](./test-with-firefox.md)._

---

## Getting Started

The steps in this section usually are run only once, when first setting up your development environment.

### System Requirements

Ensure your system has the following tools installed:

- `Python3`
- `Git`
- `curl`

> [!NOTE]
>️ These instructions assume a Git-based workflow. Mercurial (`hg`) is not used.

---

### Bootstrapping the Environment

Download Mozilla’s bootstrap python script to prepare your development environment.

```sh
curl https://hg.mozilla.org/mozilla-central/raw-file/default/python/mozboot/bin/bootstrap.py -O
```

Run the script.

```sh
python3 bootstrap.py --vcs=git
```

> [!NOTE]
> Using `--vcs=git` configures your environment to use git instead of mercurial to clone the Firefox source.

> [!WARNING]
> The `bootstrap.py` script sets up your environment by installing necessary prerequisites.
> However, it also clones the `mozilla-unified` repository by default, which
> might require some time and extra storage: we recommend not to interrupt/skip
> this step, as we experienced this can lead to potential issues later.
>
> Once the script terminates, you can safely ignore the `mozilla-unified`
> repository and Firefox building and follow the next step of these instructions.

---

### Cloning the Source

Clone the QUBIP fork of the Firefox source repository and move into the working directory:

```sh
git clone git@github.com:qubip/mozilla-central.git
cd mozilla-central
```

---

## Building Firefox

To build Firefox run the following command:

```sh
./mach build
```

This may take **a long time** (10-20 minutes or even hours) depending on your system specs.

> [!TIP]
> **Minimum requirements**:
>
> - **Memory**: 4GB RAM minimum, 8GB+ recommended.
>
> - **Disk Space**: At least 30GB of free disk space.
>
> - **Operating System**: A 64-bit installation of Linux.

---

## Running Firefox

Once built, you can launch your local Firefox build thorugh `./mach`.
However, before doing so, there are a few important things to keep in mind.

> [!IMPORTANT]
> Firefox stores all of your changes, such as your home page, toolbars, installed extensions, saved passwords, and bookmarks, in a special location called the **profile**. When launching our custom-built version of Firefox, it is crucial to specify an empty profile to ensure that the browser starts with a clean state.
>
> For testing purposes, it is always a good practice to create a **temporary profile** and reset it whenever needed. This helps to avoid any issues that might arise from leftover data or settings in the profile. In this guide, we will create a custom profile in the `/tmp/` folder, but feel free to save the profile wherever you prefer.
>
> Remember, resetting the profile is particularly useful when encountering issues with the `qryoptic` module. It allows you to start fresh and ensures that any actions or operations performed on the module or Firefox itself that may affect the module's behavior are discarded.

To launch the custom-built Firefox browser with a fresh profile, use the following commands:

1. First, remove any existing test profile and create a new, empty one:

   ```sh
   rm -rf /tmp/mytestprofile && touch /tmp/mytestprofile
   ```

2. Make sure you are in the correct working directory. Navigate to the `mozilla-central` directory first:

   ```sh
   cd mozilla-central
   ```

3. Then, launch Firefox with the newly created profile:

   ```sh
   ./mach run --profile /tmp/mytestprofile
   ```

If you encounter issues with `mach`, re-running `bootstrap.py` usually resolves missing dependencies.

> 🔗 See [Mozilla’s Getting Started Guide](https://firefox-source-docs.mozilla.org/setup/index.html) for troubleshooting help.

## Error Logging

If you do so, Firefox runs without any debug output. If you encounter any issues or want to see detailed logs from Firefox itself, you can enable logging and also increase the verbosity level by following the [Firefox Logging Documentation](https://firefox-source-docs.mozilla.org/xpcom/logging.html).

For more detailed output of the `qryoptic` module, you can use the following command, which enables verbose logging for both the `qryoptic` module and Firefox's `NSS` library:

```sh
MOZ_LOG=pipnss:4 RUST_LOG=qubip=trace ./mach run --profile /tmp/mytestprofile
```

This will provide detailed logs, allowing you to monitor the interaction between Firefox and the `qryoptic` module.

## Debugging

If you wish to debug the Firefox source code, you can pass additional options to the `./mach run` command. For more information on available options, you can always refer to the help section by typing:

```sh
./mach run --help
```

To run Firefox with debugging enabled, use the following command:

```sh
MOZ_LOG=pipnss:4 RUST_LOG=qubip=trace ./mach run --profile /tmp/mytestprofile --debugger=gdb
```

> [!TIP]
> You can use the debugger of your choice.

> [!TIP]
> The logging settings (`MOZ_LOG` and `RUST_LOG`) are optional, but they help
> provide detailed logs that can be useful for debugging.

---

## Misc

### Editor Integration

For optimal development experience [VS Code](https://code.visualstudio.com/) is fully supported but Vim, Emacs, and other editors are also supported.

- 🧠 [Editor & IDE Integration Docs](https://firefox-source-docs.mozilla.org/contributing/editors/vscode.html)
