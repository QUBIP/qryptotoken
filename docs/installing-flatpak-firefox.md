# Installing Firefox Flatpak Image

<details open="open">
<summary>Table of Contents</summary>

- [Installing Firefox Flatpak Image](#installing-firefox-flatpak-image)
  - [About](#about)
  - [Getting Started](#getting-started)
    - [System Requirements](#system-requirements)
    - [Setting up the Flatpak-Firefox Image](#setting-up-the-flatpak-firefox-image)
  - [Installing Flatpak Firefox](#installing-flatpak-firefox)
  - [Run Flatpak Firefox](#run-flatpak-firefox)
  - [Testing](#testing)

</details>

---

## About

This guide outlines the steps for setting up and running Mozilla Firefox using the Flatpak package, specifically for testing integration with the `qryptotoken` PKCS#11 module developed under the [QUBIP](https://www.qubip.eu) project.

Using Flatpak allows for a clean, sandbox environment without building Firefox from source, which is ideal for quick module testing.

Mozilla's official Flatpak builds are documented here:

- 📦 [Firefox Flatpak Packaging](https://firefox-source-docs.mozilla.org/build/buildsystem/flatpak.html#installing-the-try-build)

## Getting Started

### Prerequisites

Before proceeding, ensure that:

- You have a build of the `qryptotoken` module (`libqryptotoken_pkcs11.so`). Either
  * downloaded from the archive attached as an asset to [the latest release of qryptotoken on GitHub][qryptotoken:release:latest] (e.g., `https://github.com/QUBIP/qryptotoken/releases/download/v0.3.0/qryptotoken_v0.3.tar.gz`), or
  * compiled following [our instructions](./build-qryptotoken.md).
- You have initialized a `qryptotoken` token store (creating a `token.sql` file), as explained in [Module Initialization](./build-qryptotoken.md#module-initialization).
  * note that a pre-initialized (PIN: `1234`) `token.sql` file is also usually available among the assets of [the latest release of qryptotoken on GitHub][qryptotoken:release:latest]

### System Requirements

Ensure your system has the following tools installed:

- `flatpak`

  ```sh
  sudo dnf install flatpak
  ```

  Also, ensure that Flathub is configured as a Flatpak remote: for that, run:

  ```sh
  flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
  ```

- `tar`

  ```sh
  sudo dnf install tar
  ```

### Setting up the Flatpak-Firefox Image

QUBIP's Firefox Flatpak image can be installed in two alternative ways:
- either setting up our online remote, which always includes the latest published release of QUBIP Firefox, or
- setting up a local remote from a published repo archive, allowing to pick a specific published release of QUBIP Firefox

#### Using QUBIP's online remote

Add our online Flatpak repository:

```sh
flatpak --user --no-gpg-verify remote-add firefox-try https://a3s.fi/qubip_binaries/flatpak-firefox-try/repo
```

This command adds a user-level Flatpak remote named `firefox-try`,
backed by our online repository at
`https://a3s.fi/qubip_binaries/flatpak-firefox-try/repo`,
so that Flatpak knows where to fetch and install our custom Firefox
build from.

Check the [Troubleshooting](#troubleshooting) section below if you
encounter errors, and to verify the remote was correctly added.

#### Using a local remote from a published archive

First, download and extract the flatpak archive from
[the latest release of QUBIP Firefox on GitHub][qubip_firefox:release:latest] — this
will create a `./repo` directory, which acts as a
local Flatpak remote for installing Firefox.
(Replace `$FLATPAK_URL` with the URL of the archive file, e.g.,
`https://github.com/QUBIP/firefox/releases/download/QUBIP%2FDEVEDITION_141_QUBIP_02_RELEASE/firefox.DEVEDITION_141_QUBIP_02_RELEASE.flatpak.tar.xz`.
Replace `$FLATPAK_ARCHIVE` with the name of the downloaded file, e.g.
`firefox.DEVEDITION_141_QUBIP_02_RELEASE.flatpak.tar.xz`.)

```sh
cd $HOME/Downloads
wget $FLATPAK_URL
tar xf $FLATPAK_ARCHIVE
```

Next, add this local repository as a Flatpak remote:

```sh
flatpak --user --no-gpg-verify remote-add firefox-try $HOME/Downloads/repo/
```

This command adds a user-level Flatpak remote named `firefox-try`,
backed by the local repository files  at `$HOME/Downloads/repo/`,
so that Flatpak knows where to fetch and install our custom Firefox
build from.

Check the [Troubleshooting](#troubleshooting) section below if you
encounter errors, and to verify the remote was correctly added.

#### Troubleshooting

> [!NOTE]
> If you encounter an error like `Remote firefox-try already exists`, you have two options:
>
> - **Delete the existing remote** and re-run the command:
>
>   ```bash
>   flatpak --user remote-delete firefox-try
>   ```
>
> - **Or** choose a **different name** for the remote when adding it, for example: `firefox-hello`

To verify that it was added successfully, run:

```sh
flatpak remotes
```

You should see something like:

```sh
Name        Options
firefox-try user
flathub     user
```

> [!NOTE]
> The flathub remote may be listed as either a user or system-level remote depending on how it was originally added.

---

## Installing Flatpak Firefox

In some cases, depending on the configuration of your Linux distribution, it is
also necessary to explicitly install the required Flatpak runtime if it is
missing:

```sh
flatpak install org.freedesktop.Platform//24.08
```

This runtime provides essential libraries and services required by Flatpak
applications, including Firefox.

Install Firefox from the newly added local remote:

```sh
flatpak install firefox-try firefox
```

> [!IMPORTANT]
> Before running Firefox, ensure that the qryptotoken token file exists inside the Flatpak sandbox directory.
>
> If you have already initialized the token at $HOME/.local/share/qryptotoken/token.sql, copy it into the Flatpak-specific directory:
>
> ```sh
> mkdir -p $HOME/.var/app/org.mozilla.firefox/data/qryptotoken
> cp $HOME/.local/share/qryptotoken/token.sql $HOME/.var/app/org.mozilla.firefox/data/qryptotoken/token.sql
> ```
>
> This ensures that Firefox running inside Flatpak can access the required token file correctly.

## Run Flatpak Firefox

Now you can run the installed flatpak using:

```sh
flatpak run org.mozilla.firefox//nightly
```

However, before doing so, there are a few important things to keep in mind.

> [!IMPORTANT]
>
> ## Clean profile
>
> Firefox stores all of your changes, such as your home page, toolbars, installed extensions, saved passwords, and bookmarks, in a special location called the **profile**. When launching our flatpak version of Firefox, it is crucial to specify an empty profile to ensure that the browser starts with a clean state.
>
> For testing purposes, it is always a good practice to create a **temporary profile** and reset it whenever needed. This helps to avoid any issues that might arise from leftover data or settings in the profile. In this guide, we encourage you to reset the default firefox profile located at `~/.var/app/org.mozilla.firefox/.mozilla/firefox`
>
> Remember, resetting the profile is particularly useful when encountering issues with the `qryptotoken` module. It allows you to start fresh and ensures that any actions or operations performed on the module or Firefox itself that may affect the module's behavior are discarded.
>
> To launch the Firefox browser with a fresh profile, delete the contents of the following folder.
>
> ```sh
> rm -rf ~/.var/app/org.mozilla.firefox/.mozilla/firefox
> ```
>
> If you only want to remove information related to the **qryptotoken** module, delete the following file.
>
> ```sh
> rm ~/.var/app/org.mozilla.firefox/.mozilla/firefox/pkcs11.txt
> ```
>
> Then launch Firefox again:
>
> ```sh
> flatpak run org.mozilla.firefox//nightly
> ```

---

## Testing

_Once you’ve finished setting up Firefox using this guide and have built the
`qryptotoken` module (see: [README.md](/README.md)), you’re ready to **test** its
integration with Firefox. See:
[`test-with-firefox.md`](./test-with-firefox.md#running-firefox-from-flatpak-build)._

[qryptotoken:release:latest]: https://github.com/QUBIP/qryptotoken/releases/latest
[qubip_firefox:release:latest]: https://github.com/QUBIP/firefox/releases/latest
