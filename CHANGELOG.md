# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2021-09-27

### Added

- New properties added to resources:

  | Entity           | Properties |
  | ---------------- | ---------- |
  | `cobalt_service` | `function` |

  - The `function` property is standard to the `Service` entity class exposed by
    the JupiterOne data model and is used to describe the type of service (e.g.
    `DAST`, `SAST`)

### Changed

- Update build scripts to match integration template

## [1.1.1] - 2021-08-30

### Changed

- Changed the weblink logic to use `links.ui.uri`, returned from Cobalt API.

## 1.0.1

### Added

- Status `wont_fix` will set Finding property `open` to false (as `fixed`
  already did).

### Changed

- Updated to JupiterOne SDK version 6.0.0

## 1.0.0

### Added

- First version of the Cobalt integration, with Pentests, Findings, Users, and
  Assets
