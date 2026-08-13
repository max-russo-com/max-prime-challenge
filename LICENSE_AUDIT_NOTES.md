# License Audit Notes

This repository uses Rust crates listed in `THIRD_PARTY_LICENSES.md`.

`THIRD_PARTY_LICENSES.md` is generated from the current Rust dependency metadata and is intended to help reviewers inspect the third-party license landscape of the public MAX Prime Challenge client.

## Current audit notes

* Third-party crates remain under their own licenses.
* The MAX Prime Challenge source code remains under the repository license.
* This file does not grant additional rights beyond the repository license.
* The dependency list may change when `Cargo.toml` or `Cargo.lock` changes.

## Known dependency note

`r-efi` may appear with the license expression:

`MIT OR Apache-2.0 OR LGPL-2.1-or-later`

This is an alternative license expression. The project relies on the permissive MIT/Apache-2.0 option, not the LGPL option.

## Public repository boundary

The public repository is intended to contain:

* Rust CLI/GUI client code;
* local/demo functionality;
* official participation client functionality;
* documentation;
* dependency/license audit files.

The public repository is not intended to contain:

* server secrets;
* private admin material;
* private MAX Login implementation;
* MAX App source code;
* Hugging Face verifier tokens;
* database credentials;
* local state;
* build artifacts;
* private result archives.

Official website: https://www.max-russo.com

Repository: https://github.com/max-russo-com/max-prime-challenge
