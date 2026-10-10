# IntelliStatic

IntelliStatic is a local-first static analysis platform for Windows PE files. It pairs a single-page Streamlit dashboard with a FastAPI backend and reports structural features, binary model signals, YARA matches, and saved analysis history. Samples are read as bytes, are not written to backend disk, and are never executed.

> **Research scope:** The app trains a binary Random Forest baseline from the bundled PE metadata CSV. It evaluates on a holdout split after grouping identical feature vectors and excluding conflicting-label groups. The dataset's upstream collection URL and per-file hashes are not recorded here, only seven PE fields are used, and the model's raw class scores are not calibrated probabilities. Treat classifications as triage evidence, not ground truth. The synthetic LightGBM demo models are not used for verdicts.

## Capabilities

- In-memory file upload validation with configurable extensions and 100 MB default per-file limit.
- 77 fixed-order structural, section, import, string, byte, Rich-header, directory, and ratio features using LIEF with pefile fallback/enrichment.
- Binary Random Forest baseline using seven PE header fields present in the bundled labeled dataset; malware-family classification is not available.
- Cached YARA signature scanning with rule-specific context and false-positive caveats.
- Rule-based triage priority, plain-language reasoning, analysis UUID, SHA-256, and downloadable JSON/HTML reports.
- SQLite by default, PostgreSQL via SQLAlchemy, searchable paginated history, deletion, and batch CSV export.
- FastAPI REST endpoints with Swagger docs, optional server-side API key validation, structured logs, and CORS configuration.
- Single-page Streamlit dashboard with in-page Overview, Analyze, History, and Batch views.

## Technology

| Layer | Technology | Purpose |
|---|---|---|
| API | FastAPI, Uvicorn, Pydantic v2 | Validated HTTP contracts and OpenAPI docs |
| Dashboard | Streamlit, requests | Single-page local analyst workflow |
| Parsing | LIEF, pefile | Primary and fallback PE metadata extraction |
| Models | scikit-learn Random Forest, joblib | Binary research baseline and persisted model |
| Signatures | yara-python | In-memory rule matching |
| Persistence | SQLAlchemy, SQLite/PostgreSQL | Parameterized persistence and paginated history |
| Training | NumPy, pandas, matplotlib | Reproducible sample pipeline and evaluation plots |

## Architecture

```text
Streamlit UI → FastAPI → AnalysisService → 77 extracted PE features
                                    ├→ 7-field Random Forest baseline
                                    ├→ YARA signatures
                                    ├→ threat score and report
                                    └→ SQLAlchemy → SQLite or PostgreSQL
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/API.md](docs/API.md), and [docs/FEATURES.md](docs/FEATURES.md).

### Feature-count note

The supplied feature brief says **75** features, but its named groups total **77**. The analyzer extracts all 77; the binary baseline uses the seven fields shared with the labeled CSV. The dataset does not include malware-family labels, so the app does not claim a family prediction.

## Quick Start (Windows PowerShell)

Use **Python 3.12** for the pinned dependencies. Python 3.14 is not supported by several pinned scientific/ML packages.

```powershell
cd "$HOME\OneDrive\Documents\Intelligent_Static_Malware_Analysis\Intelligent_Static_Malware_Analysis"
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Start both API and dashboard together:

```powershell
python run_local.py
```

For separate terminals, the API can be started with `python app.py`, and the dashboard with:

```powershell
python -m streamlit run frontend/app.py
```

Train the baseline from the bundled labeled dataset before the first run:

```powershell
python ml_training/train_pe_baseline.py
```

Open the Streamlit URL printed in the terminal. The API is at `http://127.0.0.1:8000`; Swagger UI is at `http://127.0.0.1:8000/docs`.

The separate synthetic-data training pipeline remains available for development experiments, but its artifacts are intentionally not used by the app's classifier. To regenerate those experiments, run:

```powershell
python train_model.py
```

The baseline evaluation procedure, dataset limitations, and holdout results are documented in [docs/MODEL_EVALUATION.md](docs/MODEL_EVALUATION.md). Do not present synthetic-model metrics as malware-detection accuracy.

Optional local history preview (inserts only when the database has no rows):

```powershell
python database/seed.py
```

Seed rows explicitly contain a warning that they are synthetic previews and not actual analyses.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Application identity and docs link |
| GET | `/api/v1/health` | API/database health |
| GET | `/api/v1/model/info` | Baseline readiness, scope, holdout metrics and feature count |
| POST | `/api/v1/analyze` | Analyze one multipart `file` |
| POST | `/api/v1/analyze/batch` | Analyze up to 20 repeated `files` fields |
| GET | `/api/v1/history` | Searchable, paginated history |
| GET | `/api/v1/history/{analysis_id}` | Read one saved report |
| DELETE | `/api/v1/history/{analysis_id}` | Delete one report |

Upload extensions default to `.exe,.dll,.sys,.bin`; empty, unsupported, and oversized payloads are rejected server-side. The full request and response contracts are in [docs/API.md](docs/API.md).

## Configuration

Copy `.env.example` to `.env`. Important settings:

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | Local SQLite file | Use `postgresql://...` for PostgreSQL |
| `MODEL_DIR` | `./ml_training/models` | Persisted binary baseline and evaluation metadata |
| `MAX_UPLOAD_MB` | `100` | Maximum bytes per file |
| `ALLOWED_EXTENSIONS` | `.exe,.dll,.sys,.bin` | Server-side extension allowlist |
| `YARA_RULES_DIR` | `./yara_rules` | Compiled at startup |
| `CORS_ORIGINS` | Local Streamlit and localhost origins | Comma-separated exact origins |
| `API_KEY` | Unset | Optional API key checked by backend |
| `API_BASE` | `http://127.0.0.1:8000` | Frontend API URL |
| `INTELLISTATIC_API_KEY` | Unset | Optional frontend process environment; not embedded in UI source |

For local mode, bind the API to loopback. For public deployment, use HTTPS, a persistent database, a secret API key, an explicit CORS allowlist, and persistent model artifacts. The frontend can be hosted on Streamlit Community Cloud with `API_BASE` pointing to the backend. Do not expose samples, secrets, `.env`, database files, or unvalidated synthetic models.

## Training and model files

Run `python ml_training/train_pe_baseline.py` to train the binary model and generate `pe_rf_baseline_metrics.json`. The training groups duplicate feature vectors before splitting, excludes groups with conflicting labels, and evaluates on a stratified 20% holdout of distinct vectors. The API loads the model only when its feature schema and evaluation metadata are present. A missing or invalid artifact yields an `UNKNOWN` assessment.

The separate `train_model.py` path still creates synthetic multiclass experiments; those model files are not used by the app's classifier. See [docs/MODEL_EVALUATION.md](docs/MODEL_EVALUATION.md) for the bundled dataset's limits and measured results.

## Data model

`analysis_logs` is a standalone indexed table containing UUID, sanitized filename, size, SHA-256, verdict/probability, family, threat level, YARA matches, features, the full report JSON, and UTC creation time. SQLAlchemy creates the schema at startup; [database/schema.sql](database/schema.sql) is also provided.

## Security and privacy

- Samples are parsed and scanned in memory; the backend does not use `UploadFile` disk spooling, persist the bytes, or execute them.
- Only metadata, feature values, and the analysis report are stored. Do not upload files you are not authorized to analyze.
- The API validates each file and batch size itself; frontend checks are not trusted as a security boundary.
- Optional API keys are read server-side from environment variables and compared in constant time. Keys are never logged.
- Errors returned to clients do not contain stack traces. Security-relevant details are logged server-side without raw bytes.
- This project is for educational and research use. A clean result cannot guarantee a file is safe.

## Verification

Run the included layer smoke tests:

```powershell
python -m pytest
```

The tests cover a tiny generated PE's 77 numeric features, malformed input degradation, `/health`, `/model/info`, file upload response shape, history persistence, and upload validation. They do not establish malware-detection accuracy or production readiness. See the acceptance checklist in [docs/TESTING.md](docs/TESTING.md).

## License and attribution

MIT license; see [LICENSE](LICENSE). The original workspace did not contain team-member, guide, batch, or institution/domain details. Add those project-specific credits before publication.
