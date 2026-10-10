# REST API

Interactive Swagger documentation is served at `http://127.0.0.1:8000/docs`.

If `API_KEY` is configured, send it in `X-API-Key` for all endpoints. Without that setting local-development mode has no authentication.

## `GET /`

Returns application name, version and the docs path.

## `GET /api/v1/health`

Returns `{ "status": "ok", "version": "1.0.0", "database": "sqlite" }`. Database is `postgresql` when configured accordingly and `unavailable` if the database probe fails.

## `GET /api/v1/model/info`

Returns binary model availability, whether its metadata is usable, its dataset name, and its internal holdout metrics. The current baseline is binary-only; malware-family classification and a scaler are not used. Metrics are dataset-specific and the raw model class scores are not calibrated probabilities.

## `POST /api/v1/analyze`

Multipart request with one `file` field. Extensions: `.exe`, `.dll`, `.sys`, `.bin`. The service reads up to `MAX_UPLOAD_MB` bytes into memory, computes SHA-256, extracts features, evaluates, and persists a report when the database is available.

Success response:

```json
{
  "analysis_id": "uuid",
  "file_info": {"filename":"sample.exe","file_type":"Windows PE","extension":"exe","size_bytes":1280,"sha256":"..."},
  "prediction": {"binary_label":"UNKNOWN","malware_probability":null,"benign_probability":null,"confidence":null,"threat_family":"Not classified","threat_family_confidence":null,"family_probabilities":{}},
  "threat_assessment": {"threat_level":"UNKNOWN","composite_score":null,"analysis_type":"STATIC","file_executed":false,"yara_matches":[],"reasoning":"..."},
  "top_features": [], "static_features": {"machine":0}, "created_at":"2026-10-10T00:00:00Z", "warnings":[]
}
```

The score fields contain raw Random Forest class scores when the baseline is available; they are not calibrated real-world probabilities. `UNKNOWN` means no usable model could be loaded; it is not a benign verdict. A `MALICIOUS` classifier output is a triage signal and not a confirmed malware verdict.

## `POST /api/v1/analyze/batch`

Multipart request with repeated `files` fields, maximum 20. Each file is validated, analyzed in order, and persisted independently. Returns a JSON array of `AnalysisResponse` objects.

## `GET /api/v1/history`

Query parameters: `page` (≥1, default 1), `page_size` (1–100, default 20), optional `search`, `verdict`, and `threat`. Results are sorted newest first.

Returns `{ "total": 0, "items": [], "page": 1, "page_size": 20 }`.

## `GET /api/v1/history/{analysis_id}`

Returns the complete saved report for a UUID. Invalid UUIDs return 422; missing IDs return 404.

## `DELETE /api/v1/history/{analysis_id}`

Deletes one saved record and returns `{ "success": true, "message": "Deleted." }`. Invalid UUIDs return 422; missing IDs return 404.

## Error codes

| Code | Meaning |
|---|---|
| 400 | Malformed multipart payload or invalid request header. |
| 401 | API key required or invalid when authentication is enabled. |
| 404 | Requested analysis record does not exist. |
| 413 | Upload exceeds the configured individual or request size. |
| 422 | Unsupported extension, empty payload, missing field, invalid UUID or query validation. |
| 500 | Unexpected server-side failure; details remain in server logs. |

Errors use JSON `{ "detail": "..." }`; Pydantic request errors may additionally include an `errors` array.
