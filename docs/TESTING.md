# Verification checklist

## Automated smoke tests

Run `python -m pytest` from the project root. The tests cover:

- A generated tiny PE returns a deterministic 77-number feature vector.
- A malformed PE degrades without an extraction exception.
- `/api/v1/health` and `/api/v1/model/info` respond successfully.
- A fake `.exe` returns the response schema and persists a history item.
- Unsupported and empty uploads return 422.

The API smoke test does not require trained model files; the expected verdict may be `UNKNOWN`.

## Analyst manual flow

1. Start API and Streamlit with `python run_local.py`.
2. Open the local dashboard; confirm API/model status and feature count.
3. Analyze a benign sample from a controlled test corpus; review verdict, probabilities, threat reason, YARA matches, feature explanation, and the feature expander.
4. Open History; confirm the record and filters, select it, check the deletion confirmation, and remove it.
5. Batch upload three files; confirm the summary and results table, then download CSV.

Never use a sample that you are not authorized to inspect. The program itself does not execute uploaded data.

## Robustness checks

- Upload `.txt`: 422 with allowed extensions in the message.
- Upload an empty `.exe`: 422.
- Upload a file over `MAX_UPLOAD_MB`: 413.
- Stop the API: Streamlit displays a backend connection error.
- Remove or rename a model artifact: API still starts and model info warns; analyses return `UNKNOWN` rather than a made-up label.
- Stop or remove YARA: analysis continues with no matches and a warning.
- Use malformed PE bytes with an allowed extension: extraction returns a fixed-length feature vector and the response remains structured.

Passing these checks verifies application wiring only. It does not validate classifier accuracy, calibration, evasion resistance, or production security.
