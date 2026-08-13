# Security Policy

This repository contains the public MAX Prime Challenge Rust client and GUI.

The client is intentionally public and inspectable. Security must not depend on hiding the source code, API names, JSON formats, or mathematical formula.

Official MAX Prime Challenge results are not decided by the local client alone. They are valid only when accepted by the official server, assignment, submission, and verification flow.

## Core security model

The code can be read.

The client can be modified.

The API format can be inspected.

But official results are valid only if the official MAX Prime Challenge infrastructure accepts and verifies them.

A local run, local hit, modified client output, or exported JSON file is not an official result by itself.

## What must stay out of this repository

Do not commit:

* server secrets;
* database credentials;
* Hugging Face verifier tokens;
* admin tokens;
* private keys;
* `.env` files;
* real participant tokens;
* real assignment tokens;
* local app state;
* local work units;
* local results;
* local verification bundles;
* build artifacts;
* private Aruba/server code;
* private MAX Login implementation;
* MAX App source code;
* personal test data.

Common local paths that must stay out of Git:

* `target/`
* `app_state/`
* `server_client_runs/`
* `work_units/`
* `results/`
* `verification_bundles/`
* `exports/`
* `backups/`
* `checkpoints/`
* `.env`
* `.env.*`
* `*.pem`
* `*.key`

## Official participation model

The official flow is designed around:

* MAX Login / MAX App / MAX ID;
* participant registration;
* server-assigned work units;
* assignment tokens;
* local computation;
* result submission;
* server-side validation;
* remote verification for hits.

A modified client may exist, but the official server should accept only work that is authenticated, assigned, coherent with the official work unit, and verifiable.

## Reporting a vulnerability

Please report security issues with GitHub Private Vulnerability Reporting for this
repository: open the repository's **Security** tab, select **Advisories**, then
**Report a vulnerability**. This creates a private advisory visible to the
repository maintainers. If that option is unavailable, do not fall back to a
public issue containing sensitive details; contact a maintainer through the
non-sensitive project channels first to arrange a private reporting channel.

Do not publish exploit details, live tokens, private server paths, operational secrets, or attack instructions in public issues, pull requests, screenshots, videos, or discussions.

## Server compatibility required for authenticated GET requests

The new public client sends the participant token for
`api-prime-get-work.php` using the recommended
`Authorization: Bearer <participant_token>` header. The challenge and
client-device identifiers remain query parameters. The production server
already supports this header. It also temporarily accepts the legacy
`participant_token` query parameter for backward compatibility with existing
clients; new clients must not put the participant token in the URL.

Useful reports include:

* affected component;
* exact reproduction steps;
* expected behavior;
* observed behavior;
* logs with secrets removed;
* whether the issue affects local/demo mode, official participation, or both.

## Public issues

Use public GitHub issues only for non-sensitive bugs, documentation problems, build problems, usability feedback, or reproducible local/demo issues that do not expose secrets or attack paths.

Official website: https://www.max-russo.com

Repository: https://github.com/max-russo-com/max-prime-challenge
