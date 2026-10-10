# Architecture

## Data flow

```text
Single-page Streamlit dashboard
  └─ FastAPI routes and bounded in-memory upload handling
       └─ AnalysisService
            ├─ SHA-256 of sample bytes
            ├─ LIEF + pefile extraction (77 report fields)
            ├─ Seven shared PE header fields → binary Random Forest baseline
            ├─ YARA signatures → named static indicators
            ├─ transparent rule-based triage level
            └─ SQLAlchemy → SQLite or PostgreSQL history
```

## Layers

- `backend/src/api`: transport, multipart validation, health, analysis and history routes.
- `backend/src/services`: analysis orchestration, YARA matching and triage assessment.
- `backend/src/ml`: fixed-order static features and binary model loading/inference.
- `backend/src/db`: SQLAlchemy engine and `analysis_logs` model.
- `backend/src/schemas`: response contracts validated by Pydantic.
- `frontend`: one Streamlit route with in-page Overview, Analyze, History and Batch views.
- `ml_training/train_pe_baseline.py`: reproducible binary model training and holdout evaluation.
- `ml_training/train_model.py`: separate synthetic pipeline retained for experiments; its artifacts are not used for application verdicts.

## Feature extraction

Feature order is defined by `FeatureExtractor.get_feature_names()` and documented in [FEATURES.md](FEATURES.md). The extractor returns 77 finite numeric fields. The binary dataset shares only seven PE header fields with the extractor, so the model uses those seven while the report retains all 77. The dataset has no family labels; family classification is deliberately unavailable. Malformed or non-PE input should not be treated as a trustworthy model prediction.

## Binary model and evaluation

The application uses a Random Forest trained from the bundled `data/MalwareDataSet.csv`. Training groups identical seven-field feature vectors before splitting and excludes conflicting-label groups. A stratified 80/20 split over remaining unique vectors limits duplicate leakage. The model is loaded only when its feature order and evaluation metadata match the expected schema. Its raw class scores are not calibrated probabilities.

The bundled dataset's upstream collection URL and individual sample hashes are not recorded in this project. The internal holdout metrics therefore describe performance on that dataset's unique metadata vectors; they do not establish performance on new vendors, malware families, campaigns, or future samples. Full metrics and limits are in [MODEL_EVALUATION.md](MODEL_EVALUATION.md).

## Triage assessment

The threat level is a review priority based on the model's raw malware score and whether any bundled YARA rule matched. It is not a calibrated risk estimate or proof of malware. Reports preserve the exact matched rule names and explain common false-positive cases. No match does not prove a file safe.

## Persistence

`analysis_logs` stores a UUID, sanitized filename, size, SHA-256, verdict, model scores, family field (not classified by the baseline), threat level, YARA list, serialized feature vector, full response JSON and UTC timestamp. SQLite is the default; SQLAlchemy accepts PostgreSQL via `DATABASE_URL`.

## Security model

- The backend validates extensions, empty uploads, file size and batch count.
- The API reads bounded request bodies into memory. Sample bytes are not written to disk, launched, or executed.
- Optional server-side API-key authentication uses `X-API-Key` and constant-time comparison.
- CORS is restricted to configured origins. Client errors are structured and do not include stack traces.
- Logs include sanitized filename/verdict metadata, not file bytes or API keys.
- Public deployment should use HTTPS, a persistent database, and validated model artifacts. Local development binds to loopback.

## Runtime failure behavior

The API remains available if the model artifact is missing; the verdict is `UNKNOWN`. If YARA is unavailable, the report notes that signature scanning is disabled. Parser failures are captured and return the fixed feature schema without crashing the analysis request.
