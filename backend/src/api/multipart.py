from email import policy
from email.parser import BytesParser
from fastapi import HTTPException, Request

from src.core.config import settings


async def read_multipart_files(request: Request, field_name: str, max_files: int) -> list[tuple[str, bytes]]:
    """Parse multipart data from an in-memory request body without disk spooling."""
    content_type = request.headers.get("content-type", "")
    if not content_type.lower().startswith("multipart/form-data"):
        raise HTTPException(status_code=422, detail="Expected a multipart/form-data request.")
    max_body = settings.max_upload_mb * 1024 * 1024 * max_files + 2 * 1024 * 1024
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > max_body:
                raise HTTPException(status_code=413, detail="The upload request exceeds the configured size limit.")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.") from exc
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_body:
            raise HTTPException(status_code=413, detail="The upload request exceeds the configured size limit.")
        chunks.append(chunk)
    body = b"".join(chunks)
    if not body:
        raise HTTPException(status_code=422, detail="No upload data was provided.")
    envelope = (
        b"MIME-Version: 1.0\r\nContent-Type: "
        + content_type.encode("latin-1", "replace")
        + b"\r\n\r\n"
        + body
    )
    try:
        message = BytesParser(policy=policy.default).parsebytes(envelope)
        if not message.is_multipart():
            raise ValueError("Not multipart")
        uploaded: list[tuple[str, bytes]] = []
        for part in message.iter_parts():
            disposition = part.get_content_disposition()
            name = part.get_param("name", header="content-disposition")
            if disposition != "form-data" or name != field_name:
                continue
            filename = part.get_filename()
            if not filename:
                raise HTTPException(status_code=422, detail="An uploaded file must have a filename.")
            payload = part.get_payload(decode=True) or b""
            uploaded.append((filename, payload))
        if not uploaded:
            raise HTTPException(status_code=422, detail=f"No '{field_name}' file field was provided.")
        if len(uploaded) > max_files:
            raise HTTPException(status_code=422, detail=f"A maximum of {max_files} files is allowed per request.")
        return uploaded
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Malformed multipart upload.") from exc
