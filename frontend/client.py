import os
from typing import Any

import requests

API_BASE = os.getenv("API_BASE", "http://127.0.0.1:8000").rstrip("/")
API_KEY = os.getenv("INTELLISTATIC_API_KEY", "")
TIMEOUT = (5, 180)


class APIError(RuntimeError):
    pass


def request(method: str, path: str, **kwargs: Any) -> Any:
    headers = kwargs.pop("headers", {})
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    try:
        response = requests.request(method, f"{API_BASE}{path}", headers=headers, timeout=TIMEOUT, **kwargs)
    except requests.RequestException as exc:
        raise APIError("The analysis service is not responding. Check that it is running, then try again.") from exc
    if not response.ok:
        if response.status_code == 401:
            message = "The access key is missing or incorrect. Check your app settings."
        elif response.status_code == 413:
            message = "This file is too large. Choose a smaller file."
        elif response.status_code == 404:
            message = "This report could not be found. It may have been deleted."
        elif response.status_code == 422:
            message = "The file could not be checked. Choose an EXE, DLL, SYS, or BIN file and try again."
        else:
            message = "The analysis service could not finish this request. Try again."
        raise APIError(message)
    return response.json()


def health() -> dict[str, Any]:
    return request("GET", "/api/v1/health")


def model_info() -> dict[str, Any]:
    return request("GET", "/api/v1/model/info")


def analyze_file(name: str, data: bytes) -> dict[str, Any]:
    return request("POST", "/api/v1/analyze", files={"file": (name, data)})


def analyze_batch(files: list[tuple[str, bytes]]) -> list[dict[str, Any]]:
    return request("POST", "/api/v1/analyze/batch", files=[("files", item) for item in files])


def history(page: int, page_size: int, search: str = "", verdict: str = "", threat: str = "") -> dict[str, Any]:
    params = {"page": page, "page_size": page_size}
    if search:
        params["search"] = search
    if verdict and verdict != "All":
        params["verdict"] = verdict
    if threat and threat != "All":
        params["threat"] = threat
    return request("GET", "/api/v1/history", params=params)


def delete_analysis(analysis_id: str) -> dict[str, Any]:
    return request("DELETE", f"/api/v1/history/{analysis_id}")
