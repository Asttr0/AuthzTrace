# Changelog

## 0.3.0 - 2026-07-09

- Added setup preflight so broken credentials or unreadable owner fixtures abort with exit code `2` instead of producing false-clean runs.
- Added read-only execution by default, endpoint `safe: true` / `safe: false`, `--include-unsafe`, and skipped-row reporting.
- Added category-aware results (`bola`, `leak`, `setup`, `over_restrictive`, `unsafe_skipped`) across terminal, JSON, JUnit, and SARIF.
- Added stable SARIF partial fingerprints and region metadata for GitHub code scanning.
- Added GitHub Actions permissions for SARIF upload and clean/vulnerable CI smoke tests for the composite Action.
- Added PyPI Trusted Publishing workflow for tag-based releases.
- Added Python setup inside the composite Action for runner portability.
- Added `--include-unsafe` CLI option.

## 0.2.0 - 2026-07-09

- Added structured endpoint contracts for path, query, header, JSON body, and form body object IDs.
- Added exact-placeholder templating that preserves non-string ID types.
- Added explicit check validation for unknown actors and resources.
- Added response assertions: `deny_not_contains`, `not_contains`, `allow_contains`, and `no_fields`.
- Added JSON and JUnit reports alongside SARIF.
- Added `--strict`, `--base-url`, and `--timeout` CLI options.
- Added `authztrace init --from openapi.yaml` for starter contract generation.
- Added a composite GitHub Action, repository CI, `py.typed`, and Ruff configuration.

## 0.1.0 - 2026-07-09

- Initial alpha release with owner-only authorization matrix generation.
- Added terminal and SARIF reporting.
- Added deliberately vulnerable Flask API demo.
