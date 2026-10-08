from flask import Flask, request, render_template, make_response, jsonify
from collections import deque
from datetime import datetime
import os

app = Flask(__name__)

FLAGS = {
    "F1": "AICDA{POST_BYPASSES_GET_ONLY_AUTH}",
    "F2": "AICDA{HEAD_LEAKS_VIA_HEADER}",
    "F3": "AICDA{OPTIONS_REVEALS_HIDDEN_ENDPOINT}",
    "F4": "AICDA{TRACE_ECHOES_AUTH_HEADER}",
    "F5": "AICDA{PUT_WRITES_WITHOUT_AUTH}",
    "F6": "AICDA{OVERRIDE_HEADER_BYPASSES_METHOD_FILTER}",
}

REQUEST_LOG = deque(maxlen=50)


def log_request(note=""):
    REQUEST_LOG.appendleft({
        "time": datetime.now().strftime("%H:%M:%S"),
        "method": request.method,
        "path": request.path,
        "query": request.query_string.decode(),
        "note": note,
    })


def _json(obj, status=200):
    return make_response(jsonify(obj), status)


def _client_is_browser():
    """
    Detect requests coming from the challenge UI's own fetch() calls.
    Browsers set Sec-Fetch-Mode. curl and Burp do not.
    We use this to hide flags from the on-page response boxes.
    """
    return request.headers.get("Sec-Fetch-Mode", "").lower() == "cors"


# =====================================================================
# /vault — F1 (write method bypass), F2 (HEAD header),
#          F3 (OPTIONS recon), F4 (also on DELETE — TRACE is blocked
#          by Cloudflare at the edge on the public deployment)
# =====================================================================
@app.route("/vault", methods=["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS","TRACE"])
def vault():
    log_request()
    m = request.method

    if m == "GET":
        return _json({"error": "vault locked", "hint": "GET is denied by policy"}, 401)

    if m == "OPTIONS":
        # F3: recon flag returned in header, plus hint about the second endpoint.
        r = make_response("", 204)
        r.headers["Allow"] = "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE"
        r.headers["X-Vault-Note"] = "There is a second endpoint at /vault/backup"
        r.headers["X-Flag"] = FLAGS["F3"]
        return r

    if m == "HEAD":
        # F2: flag lives ONLY in the response header, never the body.
        r = make_response("", 200)
        r.headers["X-Flag"] = FLAGS["F2"]
        r.headers["X-Method-Reached"] = "HEAD"
        return r

    if m == "TRACE":
        # F4 in the traditional form: TRACE echoes the request back.
        # Note: this works on localhost, but Cloudflare strips TRACE at the
        # edge on the public deployment. F4 is therefore ALSO returned on
        # DELETE below, so students can capture it through the tunnel URL.
        body = [f"TRACE {request.path} HTTP/1.1"]
        for k, v in request.headers.items():
            body.append(f"{k}: {v}")
        body.append("")
        body.append(f"# TRACE echo flag: {FLAGS['F4']}")
        r = make_response("\n".join(body), 200)
        r.headers["Content-Type"] = "message/http"
        return r

    if m in ("POST", "PUT", "PATCH", "DELETE"):
        # F1: write methods bypass the GET-only check.
        r = _json({
            "status": "vault opened",
            "method": m,
            "note": "Check response headers for the flag." if _client_is_browser()
                    else "Flag is in the X-Flag response header.",
        })
        r.headers["X-Flag"] = FLAGS["F1"]
        # F4 alternate delivery — only on DELETE.
        if m == "DELETE":
            r.headers["X-Flag-Secondary"] = FLAGS["F4"]
        return r


# =====================================================================
# /vault/backup — F5 (PUT/PATCH with no auth), also OPTIONS hints
# =====================================================================
@app.route("/vault/backup", methods=["PUT","PATCH","DELETE","OPTIONS","HEAD","GET"])
def vault_backup():
    log_request()
    m = request.method

    if m == "GET":
        return _json({"error": "use PUT to write a backup"}, 405)

    if m == "OPTIONS":
        r = make_response("", 204)
        r.headers["Allow"] = "PUT, PATCH, DELETE, OPTIONS, HEAD"
        return r

    if m == "HEAD":
        r = make_response("", 200)
        r.headers["X-Backup-Mode"] = "writable"
        return r

    if m in ("PUT", "PATCH", "DELETE"):
        # F5: no auth on the write path. Flag in header, not body.
        r = _json({
            "status": "backup written" if m in ("PUT","PATCH") else "backup purged",
            "method": m,
            "note": "Check the X-Flag response header." if _client_is_browser()
                    else "Flag is in the X-Flag response header.",
        })
        r.headers["X-Flag"] = FLAGS["F5"]
        return r


# =====================================================================
# /api/secret — F6 (override header bypass)
# =====================================================================
@app.route("/api/secret", methods=["GET","POST","DELETE","PUT","OPTIONS"])
def api_secret():
    log_request()
    override = request.headers.get("X-HTTP-Method-Override", "").upper()
    effective = override if override else request.method

    if effective == "DELETE" and not override:
        return _json({"error": "DELETE is blocked on this endpoint"}, 403)

    if request.method == "OPTIONS":
        r = make_response("", 204)
        r.headers["Allow"] = "GET, POST, DELETE, PUT, OPTIONS"
        return r

    if request.method == "GET":
        return _json({"message": "try harder", "methods_seen": ["GET"]})

    if override:
        # F6: override header bypasses the DELETE filter.
        r = _json({
            "status": "override honored",
            "effective_method": override,
            "actual_method": request.method,
            "note": "Check the X-Flag response header." if _client_is_browser()
                    else "Flag is in the X-Flag response header.",
        })
        r.headers["X-Flag"] = FLAGS["F6"]
        return r

    return _json({"status": "received", "method": request.method})


# =====================================================================
# UI + helpers
# =====================================================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/hints")
def hints():
    return _json({
        "F1": "Only one method string is blocked on /vault. Everything else reaches the handler.",
        "F2": "The response body of HEAD is empty. The flag lives in a response header.",
        "F3": "Send OPTIONS to /vault. One of the custom X-* headers carries the flag, another names the second endpoint.",
        "F4": "TRACE echoes your request back — but Cloudflare blocks it at the edge. Try DELETE on /vault instead; a second header appears.",
        "F5": "The endpoint you found via F3 accepts PUT. No auth.",
        "F6": "Try X-HTTP-Method-Override: DELETE on a POST to /api/secret.",
        "methodology": [
            "OPTIONS every endpoint first.",
            "Then try every method with the same path.",
            "Always check response headers with curl -i or -I.",
            "For F4, remember that CDNs strip TRACE — DELETE carries the flag instead.",
        ],
    })


@app.route("/api/log")
def api_log():
    return jsonify(list(REQUEST_LOG))


@app.route("/api/submit", methods=["POST"])
def api_submit():
    data = request.get_json(silent=True) or {}
    submitted = (data.get("flag") or "").strip()
    flag_to_id = {v: k for k, v in FLAGS.items()}
    if submitted in flag_to_id:
        return jsonify({
            "ok": True,
            "flag_id": flag_to_id[submitted],
            "flag": submitted,
        })
    return jsonify({"ok": False})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=False)
