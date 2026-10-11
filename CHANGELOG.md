# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.3] - 2026-10-11

### Changed

- Pinned the `ameba` development dependency to `~> 1.7.0` instead of floating
  on its `master` branch, for reproducible lint runs.
- Restructured CI into a `lint` job (format check, ameba, compile check) and
  a `test` job (specs on Linux and macOS) that depends on it.
