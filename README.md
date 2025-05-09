<div align="center">

`qryptotoken`

  <br />
  <a href="#about"><strong>Explore the docs »</strong></a>
  <br />
  <br />
  <a href="https://github.com/qubip/qryptotoken/issues/new?assignees=&labels=bug&template=01_BUG_REPORT.md&title=bug%3A+">Report a Bug</a>
  ·
  <a href="https://github.com/qubip/qryptotoken/issues/new?assignees=&labels=enhancement&template=02_FEATURE_REQUEST.md&title=feat%3A+">Request a Feature</a>
  ·
  <a href="https://github.com/qubip/qryptotoken/issues/new?assignees=&labels=question&template=04_SUPPORT_QUESTION.md&title=support%3A+">Ask a Question</a>
</div>

<div align="center">
<br />

[![Project license](https://img.shields.io/github/license/qubip/qryptotoken.svg?style=flat-square)][LICENSE]

[![Pull Requests welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg?style=flat-square)](https://github.com/qubip/qryptotoken/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
[![code with love by qubip](https://img.shields.io/badge/%3C%2F%3E%20with%20%E2%99%A5%20by-qubip%2Fnisec-ff1414.svg?style=flat-square)](https://github.com/orgs/QUBIP/teams/nisec)

</div>

> [!CAUTION]
>
> ### Development in Progress
>
> This project is **currently in development** and **not yet ready for production use**.
>
> **Expect changes** to occur from time to time, and at this stage, some features may be unavailable.

<details open="open">
<summary>Table of Contents</summary>

- [About](#about)
  - [Supported algorithms](#supported-algorithms)
    - [Key Encapsulation Methods](#key-encapsulation-methods)
    - [Digital Signatures](#digital-signatures)
- [Getting Started](#getting-started)
- [Roadmap](#roadmap)
- [Support](#support)
- [Project assistance](#project-assistance)
- [Contributing](#contributing)
- [Authors \& contributors](#authors--contributors)
- [Security](#security)
- [License](#license)
- [Acknowledgements](#acknowledgements)

</details>

---

## About

`qryptotoken` is a pure-Rust software token implementation of a PKCS#11 loadable module for the Internet Browsing pilot of
[QUBIP](https://www.qubip.eu) project.

The project builds upon and diverges from the original [kryoptic](https://github.com/latchset/kryoptic) project with the primary distinction being the added capability to build the project as a Rust-only version.

The objective of this project is to develop a framework for integrating Post-Quantum Cryptography (PQC) functionality into the Mozilla Firefox security library called Network Security Services (NSS).

### Supported algorithms

While we do not tightly couple with specific implementation choices,
at the moment we support a limited selection of algorithms
and external implementations through our `Adapters`.

The current supported algorithms are summarized in the following tables.

> [!NOTE]
> Future updates to qryptotoken will expand its support
> for additional PQC algorithms
> and other external implementations.

#### Key Encapsulation Methods

| Algorithm  | Adapter |
| ---------- | ------- |
| ML-KEM 768 | libcrux |

#### Digital Signatures

| Algorithm | Adapter |
| --------- | ------- |
| ML-DSA-65 | libcrux |

## Getting Started

To get started, first build the `qryptotoken` module by following the [build guide](./docs/build-qryptotoken.md). It will walk you through installing the necessary dependencies, setting up the token environment, and initializing the module using the `pkcs11-tool`.

Once you've successfully built and initialized the module, you're ready to test it with Firefox.

You have two options for setting up Firefox:

- You can build Firefox from source by following a detailed [setup guide](./docs/build-firefox-from-source.md), which is ideal if you want full control and debugging capabilities.
- Or you can use a preconfigured Flatpak image, which is quicker to set up and ready for testing. Setup instructions are provided in the dedicated [Flatpak guide](./docs/installing-flatpak-firefox.md).

Pick the option that suits your needs best.

After your Firefox environment is ready, just follow the [testing guide](./docs/test-with-firefox.md). It will show you how to load the module, and run the interoperability and login tests.

<!--
### Prerequisites

> **[?]**
> What are the project requirements/dependencies?

### Installation

> **[?]**
> Describe how to install and get started with the project.

## Usage

> **[?]**
> How does one go about using it?
> Provide various use cases and code examples here.
-->

## Roadmap

See the [open issues](https://github.com/qubip/qryptotoken/issues) for a list of proposed features (and known issues).

- [Top Feature Requests](https://github.com/qubip/qryptotoken/issues?q=label%3Aenhancement+is%3Aopen+sort%3Areactions-%2B1-desc) (Add your votes using the 👍 reaction)
- [Top Bugs](https://github.com/qubip/qryptotoken/issues?q=is%3Aissue+is%3Aopen+label%3Abug+sort%3Areactions-%2B1-desc) (Add your votes using the 👍 reaction)
- [Newest Bugs](https://github.com/qubip/qryptotoken/issues?q=is%3Aopen+is%3Aissue+label%3Abug)

## Support

Reach out to the maintainers at one of the following places:

- [GitHub issues](https://github.com/qubip/qryptotoken/issues/new?assignees=&labels=question&template=04_SUPPORT_QUESTION.md&title=support%3A+)
- <security@romen.dev> to disclose security issues according to our [security documentation](docs/SECURITY.md).
- <coc@romen.dev> to report violations of our [Code of Conduct](docs/CODE_OF_CONDUCT.md).
- Details about the GPG keys to encrypt reports are included in our [security documentation](docs/SECURITY.md).

## Project assistance

If you want to say **thank you** or/and support active development:

- Add a [GitHub Star](https://github.com/qubip/qryptotoken) to the project.
- Mention this project on your social media of choice.
- Write interesting articles about the project, and cite us.

Together, we can make Qryptotoken **better**!

## Contributing

The GitHub repository primarily serves as a mirror,
and will be updated every time a new version is released.
It might not always be updated with the latest commits in between releases.
However, contributions are still very welcome!

Please read [our contribution guidelines](docs/CONTRIBUTING.md), and thank you for being involved!

## Authors & contributors

The original setup of this repository is by [NISEC](https://github.com/orgs/QUBIP/teams/nisec).

For a full list of all authors and contributors, see [the contributors page](https://github.com/qubip/qryptotoken/contributors).

## Security

In this project, we aim to follow good security practices, but 100% security cannot be assured.
This crate is provided **"as is"** without any **warranty**. Use at your own risk.

_For more information and to report security issues, please refer to our [security documentation](docs/SECURITY.md)._

## License

This project is licensed under the
[**GNU General Public License v3.0**](https://www.gnu.org/licenses/gpl-3.0-standalone.html)
([GPL-3.0-only](https://spdx.org/licenses/GPL-3.0-only.html)).

```text
qryptotoken - a kryoptic fork tailored for PQC

Copyright (C) 2023-2024 Simo Sorce, Jakub Jelen
Copyright (C) 2023-2025 Tampere University

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

```

See [LICENSE][LICENSE] for more information.

[LICENSE]: LICENSE.txt

## Acknowledgements

This work has been developed within the QUBIP project (<https://www.qubip.eu>),
funded by the European Union under the Horizon Europe framework programme
[grant agreement no. 101119746](https://doi.org/10.3030/101119746).
