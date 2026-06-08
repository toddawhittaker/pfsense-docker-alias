# AGENTS.md

## Project context

This repository contains a lightweight Python Docker service that listens to Docker container events and updates pfSense DNS aliases through the unofficial pfSense REST API.

## Working rules

- Make small, reviewable changes.
- Preserve Docker-based deployment.
- Keep configuration environment-variable driven.
- Do not introduce new runtime dependencies unless explicitly approved.
- Treat pfSense API credentials as sensitive.
- Never log API tokens, secrets, full authorization headers, or sensitive environment values.
- Prefer clear error handling around Docker API calls, pfSense API calls, network failures, and malformed labels.
- Keep README examples aligned with the actual code and compose file.
- After changing Python files, run:
  - `python -m py_compile main.py pfsense.py`
- After changing Docker-related files, run:
  - `docker build -t pfsense-docker-alias .`

## Style

- Prefer straightforward Python.
- Avoid over-engineering.
- Use explicit names and boring control flow.
- Keep log messages useful but not noisy.

## Release rules

- Document user-facing behavior changes.
- Note changed environment variables, labels, or compose examples.
- Keep release notes in plain Markdown.