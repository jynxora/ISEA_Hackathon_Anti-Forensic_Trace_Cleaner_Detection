"""
backend_main.py
───────────────
FastAPI server for WipeTrace.

Endpoints:
    POST   /upload              Stream disk image, return session ID + SHA-256
    POST   /hash                Re-hash a stored image on demand
    POST   /scan                Trigger wipe detection scan (background task)
    GET    /scan/status/{sid}   Poll scan progress
    GET    /results/{sid}       Fetch completed analysis JSON
    DELETE /session/{sid}       Clean up uploaded image + results

Run:
    pip install fastapi uvicorn aiofiles python-multipart
    uvicorn backend_main:app --host 0.0.0.0 --port 8000
"""

import uuid
from pathlib import Path

import aiofiles
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from hashing import hash_file
from scanner import run_scan

app = FastAPI(title="WipeTrace Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Storage config ────────────────────────────────────────────────────────────
UPLOAD_DIR  = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

MAX_SIZE    = 8 * 1024 * 1024 * 1024   # 8 GB hard ceiling
CHUNK_SIZE  = 1 * 1024 * 1024           # 1 MB streaming chunks

# ── In-memory scan state ──────────────────────────────────────────────────────
# Maps session_id → { "status": "pending|running|done|error", "progress": 0-100 }
scan_state: dict[str, dict] = {}


# ── POST /upload ──────────────────────────────────────────────────────────────
@app.post("/upload")
async def upload_image(file: UploadFile = File(...)):
    """
    Stream disk image to disk in 1 MB chunks.
    Delegates SHA-256 computation to hashing.py after write completes.
    Returns session_id, sha256, size — all needed for the scan step.
    """
    session_id  = "SID-" + uuid.uuid4().hex[:8].upper()
    save_path   = UPLOAD_DIR / f"{session_id}_{file.filename}"
    total_bytes = 0

    # ── Stream to disk (never loads full file into RAM) ───────────────────────
    try:
        async with aiofiles.open(save_path, "wb") as out:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break

                total_bytes += len(chunk)

                if total_bytes > MAX_SIZE:
                    await out.close()
                    save_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds {_fmt(MAX_SIZE)} maximum."
                    )

                await out.write(chunk)

    except HTTPException:
        raise
    except Exception as e:
        save_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=str(e))

    # ── Hash via hashing.py ───────────────────────────────────────────────────
    try:
        sha256 = hash_file(str(save_path))
    except Exception as e:
        save_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Hashing failed: {e}")

    # Register session as ready for scanning
    scan_state[session_id] = {
        "status":      "pending",
        "progress":    0,
        "stored_path": str(save_path),
        "filename":    file.filename,
        "sha256":      sha256,
        "json_path":   None,
    }

    return JSONResponse({
        "session_id":  session_id,
        "filename":    file.filename,
        "size_bytes":  total_bytes,
        "size_human":  _fmt(total_bytes),
        "sha256":      sha256,
        "stored_path": str(save_path),
        "status":      "ready",
    })


# ── POST /scan ────────────────────────────────────────────────────────────────
@app.post("/scan")
async def start_scan(body: dict, background_tasks: BackgroundTasks):
    """
    Trigger the wipe detection engine on a previously uploaded image.

    Request body: { "session_id": "SID-XXXXXXXX" }

    The scan runs in a FastAPI background task so the endpoint returns
    immediately. Poll GET /scan/status/{session_id} for progress.
    """
    session_id = body.get("session_id", "")
    if not session_id or session_id not in scan_state:
        raise HTTPException(status_code=404, detail="Session not found.")

    state = scan_state[session_id]
    if state["status"] == "running":
        raise HTTPException(status_code=409, detail="Scan already running.")

    state["status"]   = "running"
    state["progress"] = 0

    background_tasks.add_task(
        _run_scan_task,
        session_id  = session_id,
        image_path  = state["stored_path"],
        sha256      = state["sha256"],
    )

    return JSONResponse({"session_id": session_id, "status": "running"})


async def _run_scan_task(session_id: str, image_path: str, sha256: str):
    """Background task: run scan pipeline, update scan_state on completion."""
    state = scan_state[session_id]

    def _progress(done: int, total: int):
        state["progress"] = int((done / total) * 100) if total > 0 else 0

    try:
        json_path = run_scan(
            image_path  = image_path,
            session_id  = session_id,
            sha256      = sha256,
            output_dir  = UPLOAD_DIR,
            progress_cb = _progress,
        )
        state["status"]    = "done"
        state["progress"]  = 100
        state["json_path"] = str(json_path)

    except Exception as e:
        state["status"] = "error"
        state["error"]  = str(e)


# ── GET /scan/status/{session_id} ─────────────────────────────────────────────
@app.get("/scan/status/{session_id}")
async def scan_status(session_id: str):
    """
    Poll scan progress.

    Returns: { status, progress (0-100), json_path (when done) }
    Frontend polls this every 2 s until status == "done" or "error".
    """
    if session_id not in scan_state:
        raise HTTPException(status_code=404, detail="Session not found.")

    state = scan_state[session_id]
    return JSONResponse({
        "session_id": session_id,
        "status":     state["status"],
        "progress":   state["progress"],
        "json_path":  state.get("json_path"),
        "error":      state.get("error"),
    })


# ── GET /results/{session_id} ─────────────────────────────────────────────────
@app.get("/results/{session_id}")
async def get_results(session_id: str):
    """
    Return the full analysis JSON once scan is complete.
    This is what analysis_dashboard.html fetches to replace mock data.
    """
    if session_id not in scan_state:
        raise HTTPException(status_code=404, detail="Session not found.")

    state = scan_state[session_id]

    if state["status"] != "done":
        raise HTTPException(
            status_code=425,
            detail=f"Scan not complete yet. Status: {state['status']}"
        )

    json_path = Path(state["json_path"])
    if not json_path.exists():
        raise HTTPException(status_code=404, detail="Results file not found.")

    async with aiofiles.open(json_path, "r") as f:
        content = await f.read()

    import json
    return JSONResponse(json.loads(content))


# ── POST /hash ────────────────────────────────────────────────────────────────
@app.post("/hash")
async def rehash_file(body: dict):
    """
    Re-hash a stored image for integrity verification.
    Request body: { "stored_path": "uploads/SID-XXXXXXXX_filename.dd" }
    """
    stored_path = body.get("stored_path", "")
    if not stored_path:
        raise HTTPException(status_code=400, detail="stored_path is required.")

    path = Path(stored_path)
    if not path.resolve().is_relative_to(UPLOAD_DIR.resolve()):
        raise HTTPException(status_code=403, detail="Access denied.")
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found.")

    try:
        sha256 = hash_file(str(path))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hashing failed: {e}")

    return JSONResponse({"stored_path": stored_path, "sha256": sha256, "status": "verified"})


# ── DELETE /session/{session_id} ──────────────────────────────────────────────
@app.delete("/session/{session_id}")
async def delete_session(session_id: str):
    """Delete uploaded image + results JSON. Call after analysis is exported."""
    deleted = []

    for f in UPLOAD_DIR.glob(f"{session_id}_*"):
        f.unlink()
        deleted.append(f.name)

    results_json = UPLOAD_DIR / f"analysis_{session_id}.json"
    if results_json.exists():
        results_json.unlink()
        deleted.append(results_json.name)

    scan_state.pop(session_id, None)
    return {"deleted": deleted}


# ── Utility ───────────────────────────────────────────────────────────────────
def _fmt(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.2f} {unit}"
        b //= 1024
    return f"{b:.2f} TB"
