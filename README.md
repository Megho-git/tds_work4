# Safe AI Mailroom Agent

FastAPI implementation of the `ga5-mailroom-action-gate/v2` propose/commit API.

## Deploy

1. Extract this ZIP and push the contents of `safe_ai_mailroom_agent/` to the root of a new GitHub repository (or use the included `render.yaml` Blueprint).
2. In Render, set `AI_API_KEY` to a private key for a compatible OpenAI-style chat-completions provider. Never commit the key.
3. Keep `AI_BASE_URL=https://aipipe.org/openrouter/v1`; `AI_MODEL` defaults to `openrouter/free`, which requires that your provider account can access a free routed model. A provider HTTP 402 means the provider has denied usage/credits; it is not a Render routing problem.
4. Deploy and verify `GET /health`.
5. Submit the public HTTPS service URL for the single JSON POST endpoint, e.g. `https://<service>.onrender.com/`. The endpoint accepts `operation: propose` and `operation: commit`.

## Implemented contract

- Exact profile `ga5-mailroom-action-gate/v2` and propose/commit request envelopes.
- `inputDigest` is SHA-256 of canonical compact JSON for the `dossiers` array only.
- Deterministic `callId`s and content-addressed dossier decision cache.
- Frozen exact target/payload schemas for all six actions; unknown target/payload fields are rejected.
- Evidence citations must be unique, exact `lineId`s present in that dossier.
- Per-evaluation Ed25519 public JWK storage; each receipt signature is checked against the canonical signed envelope.
- Exact proposal digest normalization, all-receipts-before-commit validation, accepted/rejected outcomes, persistent receipt storage, commit replay, and changed-content conflicts.
- SQLite-backed evaluation state and cache.
- Synchronous model requests run in a worker thread so the `/health` endpoint remains responsive during inference.
- Sanitized exception messages and tracebacks are logged for diagnosing model/output failures without logging bearer tokens or full dossier contents.

## Required environment

- `AI_API_KEY` (required)
- `AI_BASE_URL` (default `https://aipipe.org/openrouter/v1`)
- `AI_MODEL` (default `openrouter/free`)
- `DATABASE_PATH` (default `./data/mailroom.sqlite3`)
- `MAX_BODY_BYTES` (default 12 MiB)
- `MAX_OUTPUT_TOKENS` (default 16000)

Use a persistent disk/database if the hosting provider may discard local files across restarts. Verify the AI provider succeeds before using a limited grading Check; HTTP 402 from the provider is propagated as a safe HTTP 502 by this service.

## Scope note

The service proposes actions only and does not send email or modify external mail systems. It records an `executed` outcome only for a valid signed receipt with `accepted: true`, exactly as required by the supplied contract.
