# Contributing to MAX Prime Challenge

Thank you for reviewing or contributing to MAX Prime Challenge.

This repository is source-available for public inspection, local builds, technical review, security review, and participation in the official MAX Prime Challenge flow.

## Project scope

MAX Prime Challenge is not a generic random prime search.

The core workflow is:

`Campaign -> Work Units -> Run -> Verify -> Report`

The public client is Rust-based and includes CLI + GUI usage.

## Useful contributions

Useful contributions include:

* build fixes;
* documentation improvements;
* security hardening;
* clearer error messages;
* reproducibility improvements;
* local/demo workflow fixes;
* verification/export improvements;
* dependency/license audit improvements.

## Keep out of this repository

Please do not submit:

* secrets, tokens, private keys, or real participant data;
* build artifacts or binaries;
* `target/`;
* local app state;
* local work units, results, or bundles unless explicitly requested as public examples;
* private Aruba/server code;
* private MAX Login implementation;
* MAX App source code;
* unrelated rewrites of the project architecture.

These limits exist because this repository is public and is meant to contain only the inspectable client side of MAX Prime Challenge.

## Mathematical wording

Current primality results should be described as probable primes unless stronger certification is explicitly added and documented.

Do not describe Miller-Rabin probable-prime results as definitive mathematical prime certifications.

## Official vs local results

Local/demo results are useful for testing and reproducibility.

Official MAX Prime Challenge results are valid only when accepted by the official server and verification flow.

## Pull requests

Keep pull requests focused and small.

Explain:

* what changed;
* why it changed;
* how it was tested;
* whether it affects CLI, GUI, local/demo mode, or official participation mode.

## License

By contributing, you agree that your contribution may be included in this repository under the repository license.

Official website: https://www.max-russo.com

Repository: https://github.com/max-russo-com/max-prime-challenge

