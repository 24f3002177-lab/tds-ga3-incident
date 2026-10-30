"""main.py - thin web layer. All logic lives in core.py."""
import asyncio
import json
import traceback

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import core

MAX_BODY = 4 * 1024 * 1024
app = FastAPI(redirect_slashes=False)


def err(status, code):
    return JSONResponse(status_code=status, content={"error": {"code": code}})


async def read_json(request):
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY:
        raise core.Reject(413, "BODY_TOO_LARGE")
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise core.Reject(413, "BODY_TOO_LARGE")
    try:
        body = json.loads(raw)
    except Exception:
        raise core.Reject(400, "INVALID_JSON")
    if not isinstance(body, dict):
        raise core.Reject(400, "INVALID_REQUEST")
    return body


async def run(fn, *args):
    try:
        return JSONResponse(status_code=200, content=await asyncio.to_thread(fn, *args))
    except core.Reject as r:
        print("REJECT", r.status, r.code, flush=True)
        return err(r.status, r.code)
    except Exception:
        traceback.print_exc()
        return err(500, "INTERNAL_ERROR")


@app.get("/")
def home():
    return {"status": "running"}


@app.post("/v2/incidents")
async def create(request: Request):
    try:
        body = await read_json(request)
    except core.Reject as r:
        return err(r.status, r.code)
    return await run(core.handle_create, body, request.headers.get("traceparent"),
                     request.headers.get("tracestate"))


@app.post("/v2/incidents/{run_id}/receipts")
async def receipts(run_id: str, request: Request):
    try:
        body = await read_json(request)
    except core.Reject as r:
        return err(r.status, r.code)
    return await run(core.handle_receipt, run_id, body)


@app.get("/dbg-7f3k9q/incidents")
async def debug_incidents():
    return JSONResponse(content=core.debug_dump())

@app.middleware("http")
async def log_everything(request: Request, call_next):
    response = await call_next(request)
    if not request.url.path.startswith("/dbg"):
        keep = ("traceparent", "tracestate", "content-type", "user-agent", "accept")
        core.debug_note("-", "http", {"method": request.method, "path": request.url.path,
                                      "status": response.status_code,
                                      "headers": {k: v for k, v in request.headers.items() if k.lower() in keep}})
    return response



@app.get("/v2/incidents/{run_id}")
async def get_run(run_id: str):
    return await run(core.handle_get, run_id)
