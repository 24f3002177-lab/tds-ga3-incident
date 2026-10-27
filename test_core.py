"""python test_core.py  - fake grader, fake planner, no internet, no model."""
import copy, json, os, tempfile, time
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "t.db")
import core

TRANSCRIPT = "\n".join("[ev_%03d] line %d" % (i, i) for i in range(1, 30))
SECRET = "TOKEN-SUPER-SECRET-123"


def body(run, effect="rollback_deployment"):
    return {"profile": core.PROFILE, "runId": run, "agentName": "incident-response",
            "publicMarker": "mk-" + run, "sensitive": {"accessToken": SECRET, "privateNote": "private-note-xyz"},
            "incident": {"incidentId": "INC1", "title": "t", "service": "api", "severity": "SEV-1",
                         "transcript": TRANSCRIPT, "allowedRootCauses": ["bad_deploy", "traffic_spike"]},
            "toolCatalog": [
                {"name": "query_metrics", "description": "", "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}, "required": ["service"]}},
                {"name": "get_logs", "description": "", "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}, "required": ["service"]}},
                {"name": "rollback_deployment", "description": "", "inputSchema": {"type": "object"}},
                {"name": "scale_service", "description": "", "inputSchema": {"type": "object"}}],
            "policy": {"maximumDiagnostics": 3, "effectTools": ["rollback_deployment", "scale_service"],
                       "approvalRequiredFor": ["rollback_deployment", "disable_feature"], "doNotExport": ["private-note-xyz"]}}


def planner_for(effect):
    def p(b):
        t0 = time.time_ns()
        plan = core.validate_plan({"rootCause": "bad_deploy", "evidence": ["ev_001", "ev_002"],
            "diagnostics": [{"toolName": "query_metrics", "arguments": {"service": "api"}, "evidence": ["ev_001"]},
                            {"toolName": "get_logs", "arguments": {"service": "api"}, "evidence": ["ev_002"]}],
            "effect": {"toolName": effect, "arguments": {"deploy": "d-9"}, "evidence": ["ev_003"]}}, b)
        return plan, "test-model", t0, time.time_ns()
    return p


ok = []
def check(name, cond):
    ok.append(bool(cond)); print(("PASS " if cond else "FAIL ") + name)

def raises(code, fn, *a):
    try: fn(*a)
    except core.Reject as r: return r.status == code
    return False

def outcome(d, status, **kw):
    o = {"actionId": d["actionId"], "callId": d["callId"], "attempt": d["attempt"], "status": status,
         "resultClass": "diagnosis_confirmed" if status == 200 else None, "nonce": "n-" + d["actionId"] + str(d["attempt"])}
    if status == 0: o["errorType"] = "timeout"
    return o

# ---- scenario 1: parallel diagnostics, 503 retry, approval, destructive effect
core.PLANNER = planner_for("rollback_deployment")
b = body("run-one-aaaa")
tp = "00-" + "ab" * 16 + "-" + "cd" * 8 + "-01"
r1 = core.handle_create(b, tp, "vendor=x")
d = r1["dispatches"]
check("2 parallel diagnostics, no approvals", len(d) == 2 and r1["approvals"] == [] and r1["status"] == "waiting")
check("trace continued + tracestate kept", d[0]["traceparent"].split("-")[1] == "ab" * 16 and d[0]["tracestate"] == "vendor=x")
check("replay create identical", core.handle_create(b, tp, "vendor=x") == r1)
bad = copy.deepcopy(b); bad["incident"]["title"] = "changed"
check("changed run -> 409", raises(409, core.handle_create, bad))
rc1 = {"receiptId": "rcpt-0001", "outcomes": [outcome(d[0], 503), outcome(d[1], 200)]}
r2 = core.handle_receipt("run-one-aaaa", rc1)
check("503 -> exactly one retry, attempt 2, same ids, no approval",
      len(r2["dispatches"]) == 1 and r2["dispatches"][0]["attempt"] == 2 and r2["dispatches"][0]["actionId"] == d[0]["actionId"]
      and r2["dispatches"][0]["traceparent"] != d[0]["traceparent"] and r2["approvals"] == [])
check("receipt replay identical", core.handle_receipt("run-one-aaaa", rc1) == r2)
bad_rc = copy.deepcopy(rc1); bad_rc["outcomes"][1]["status"] = 500
check("same receiptId changed -> 409", raises(409, core.handle_receipt, "run-one-aaaa", bad_rc))
check("stale attempt -> 400", raises(400, core.handle_receipt, "run-one-aaaa", {"receiptId": "rcpt-0002", "outcomes": [outcome(d[0], 200)]}))
r3 = core.handle_receipt("run-one-aaaa", {"receiptId": "rcpt-0003", "outcomes": [outcome(r2["dispatches"][0], 200)]})
ap = r3["approvals"]
check("approval requested, zero dispatches", r3["dispatches"] == [] and len(ap) == 1 and ap[0]["toolName"] == "rollback_deployment"
      and ap[0]["argumentsDigest"] == core.sha(core.canon({"deploy": "d-9"})))
check("unknown approval -> 400", raises(400, core.handle_receipt, "run-one-aaaa", {"receiptId": "rcpt-x", "approvals": [{"approvalId": "nope", "decision": "approved", "nonce": "z"}]}))
r4 = core.handle_receipt("run-one-aaaa", {"receiptId": "rcpt-0004", "approvals": [{"approvalId": ap[0]["approvalId"], "decision": "approved", "nonce": "appr-nonce-1"}]})
e = r4["dispatches"][0]
check("effect carries approvalId+nonce, same reserved actionId", e["approvalId"] == ap[0]["approvalId"] and e["approvalNonce"] == "appr-nonce-1" and e["actionId"] == ap[0]["actionId"])
r5 = core.handle_receipt("run-one-aaaa", {"receiptId": "rcpt-0005", "outcomes": [outcome(e, 200)]})
check("completed", r5["status"] == "completed" and r5["chosenEffect"] == "rollback_deployment" and r5["dispatches"] == [] and r5["approvals"] == [])
check("actionLog has 4 dispatches, receiptLog has 5 entries", len(r5["actionLog"]) == 4 and len(r5["receiptLog"]) == 5)
check("GET == final state", core.handle_get("run-one-aaaa") == r5)
check("replay create after completion == final", core.handle_create(b, tp, "vendor=x") == r5)
check("no secrets anywhere", SECRET not in json.dumps(r5) and "private-note-xyz" not in json.dumps(r5))
check("receipt after completion -> 400", raises(400, core.handle_receipt, "run-one-aaaa", {"receiptId": "rcpt-9", "outcomes": [outcome(e, 200)]}))

sp = r5["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
names = [s["name"] for s in sp]
tids = {s["traceId"] for s in sp}
check("one trace id, = incoming", tids == {"ab" * 16})
check("span counts", names.count("POST /v2/incidents") == 1 and names.count("chat incident-plan") == 1
      and names.count("incident.join") == 1 and names.count("approval_gate") == 1
      and sum(n.startswith("execute_tool ") for n in names) == 3 and sum(n.startswith("POST tool/") for n in names) == 4)
check("all spans carry run id + marker", all({"ga5.run.id", "ga5.public.marker"} <= {a["key"] for a in s["attributes"]} for s in sp))
client_ids = {s["spanId"] for s in sp if s["name"].startswith("POST tool/")}
check("every dispatch traceparent span id is a CLIENT span", all(x["traceparent"].split("-")[2] in client_ids for x in r5["actionLog"]))
cl = [s for s in sp if s["name"].startswith("POST tool/")]
def at(s, k): return next(a["value"] for a in s["attributes"] if a["key"] == k)
c503 = [s for s in cl if any(a["key"] == "error.type" and a["value"]["stringValue"] == "503" for a in s["attributes"])]
check("503 span: status 2, resend 0; retry resend 1", len(c503) == 1 and c503[0]["status"]["code"] == 2 and at(c503[0], "http.request.resend_count")["intValue"] == 0
      and any(at(s, "http.request.resend_count")["intValue"] == 1 for s in cl))
check("success spans have no error.type", all(not any(a["key"] == "error.type" for a in s["attributes"]) for s in cl if s["status"]["code"] != 2))
check("parents all exist", all(s.get("parentSpanId") in {x["spanId"] for x in sp} or s["name"] == "POST /v2/incidents" for s in sp))
check("join links both diagnostics", len([s for s in sp if s["name"] == "incident.join"][0]["links"]) == 2)

# ---- scenario 2: timeout suppresses the effect
b2 = body("run-two-bbbb"); r = core.handle_create(b2)
d = r["dispatches"]
r = core.handle_receipt("run-two-bbbb", {"receiptId": "rcpt-t1", "outcomes": [outcome(d[0], 0)]})
check("waits for the sibling diagnostic", r["status"] == "waiting" and r["dispatches"] == [])
r = core.handle_receipt("run-two-bbbb", {"receiptId": "rcpt-t2", "outcomes": [outcome(d[1], 200)]})
check("timeout -> failed, no effect, no approval", r["status"] == "failed" and r["chosenEffect"] is None and r["suppressed"] and len(r["actionLog"]) == 2 and r["approvals"] == [])
tsp = r["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
check("timeout span error.type=timeout", any(a["key"] == "error.type" and a["value"]["stringValue"] == "timeout" for s in tsp for a in s["attributes"]))

# ---- scenario 3: non-destructive effect goes out directly
core.PLANNER = planner_for("scale_service")
b3 = body("run-three-cccc"); r = core.handle_create(b3); d = r["dispatches"]
r = core.handle_receipt("run-three-cccc", {"receiptId": "rcpt-s1", "outcomes": [outcome(d[0], 200), outcome(d[1], 200)]})
check("scale_service dispatched directly, no approval", len(r["dispatches"]) == 1 and r["approvals"] == [] and r["dispatches"][0]["phase"] == "effect" and "approvalId" not in r["dispatches"][0])

# ---- validation
check("bad profile -> 400, nothing created", raises(400, core.handle_create, {**body("run-bad-dddd"), "profile": "x"}) and core.load_run("run-bad-dddd")[1] is None)
check("malformed -> 422", raises(422, core.handle_create, {"profile": core.PROFILE, "runId": "run-m-eeee"}))
check("unknown run receipt -> 404", raises(404, core.handle_receipt, "nope-nope", {"receiptId": "rcpt-1", "outcomes": [outcome(d[0], 200)]}))
print("\nALL GOOD" if all(ok) else "\nSOMETHING FAILED (%d)" % ok.count(False))
