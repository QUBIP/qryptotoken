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

This guide outlines the steps for setting up and running Mozilla Firefox using the Flatpak package, specifically for testing integration with the `qryoptic` PKCS#11 module developed under the [QUBIP](https://www.qubip.eu) project.

Using Flatpak allows for a clean, sandbox environment without building Firefox from source, which is ideal for quick module testing.

Mozilla's official Flatpak builds are documented here:

- 📦 [Firefox Flatpak Packaging](https://firefox-source-docs.mozilla.org/build/buildsystem/flatpak.html#installing-the-try-build)

## Getting Started

### System Requirements

Ensure your system has the following tools installed:

- `flatpak`

  ```sh
  sudo apt install flatpak
  ```

  Also, ensure that Flathub is configured as a Flatpak remote: for that, run:

  ```sh
  flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
  ```

- `tar`

  ```sh
  sudo apt install tar
  ```

### Setting up the Flatpak-Firefox Image

First, download and extract the target.flatpak.tar.xz archive — this will create a ./repo directory, which acts as a local Flatpak source for installing Firefox.

```sh
cd ~/Downloads
wget https://a3s.fi/qubip_binaries/target.flatpak.tar.xz
tar xf target.flatpak.tar.xz
```

Next, add this local repository as a Flatpak remote:

```sh
flatpak --user --no-gpg-verify remote-add firefox-try ~/Downloads/repo/
```

This command adds a user-level Flatpak remote named firefox-try, which would create a reference to your local Firefox repository (./repo) so that Flatpak knows where to fetch and install the custom Firefox build from.

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
> Before running Firefox, ensure that the qryoptic token file exists inside the Flatpak sandbox directory.
>
> If you have already initialized the token at $HOME/.local/share/qryoptic/token.sql, copy it into the Flatpak-specific directory:
>
> ```sh
> mkdir -p $HOME/.var/app/org.mozilla.firefox/data/qryoptic
> cp $HOME/.local/share/qryoptic/token.sql $HOME/.var/app/org.mozilla.firefox/data/qryoptic/token.sql
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
> Remember, resetting the profile is particularly useful when encountering issues with the `qryoptic` module. It allows you to start fresh and ensures that any actions or operations performed on the module or Firefox itself that may affect the module's behavior are discarded.
>
> To launch the Firefox browser with a fresh profile, delete the contents of the following folder.
>
> ```sh
> rm -rf ~/.var/app/org.mozilla.firefox/.mozilla/firefox
> ```
>
> If you only want to remove information related to the **qryoptic** module, delete the following file.
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
`qryoptic` module (see: [README.md](/README.md)), you’re ready to **test** its
integration with Firefox. See:
[`test-with-firefox.md`](./test-with-firefox.md#running-firefox-from-flatpak-build)._
