from flask import Flask, request, render_template, jsonify, make_response

app = Flask(__name__)

FLAG = "AICDA{HTTP_METHOD_BYPASS_MASTER}"
SECOND_FLAG = "AICDA{FILTER_BYPASS_VIA_METHOD}"
THIRD_FLAG = "AICDA{TRACE_ENABLED_INFO_LEAK}"

# =====================================================================
# TARGET 1: /admin/reset
# Flawed logic: only GET is "protected". Every other method bypasses.
# OPTIONS leaks the attack surface. TRACE is intentionally enabled here.
# =====================================================================
@app.route(
    "/admin/reset",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
def admin_reset():
    method = request.method

    if method == "GET":
        return "Access Denied: Admin authentication required for GET requests.", 401

    if method == "OPTIONS":
        # Leaks the full method list — recon gold
        resp = make_response("", 204)
        resp.headers["Allow"] = "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS"
        return resp

    if method == "HEAD":
        # Body is stripped by Flask, but the handler still executes.
        # The flag is placed in a custom header so it survives HEAD.
        resp = make_response("", 200)
        resp.headers["X-Admin-Flag"] = FLAG
        resp.headers["X-Method-Used"] = "HEAD"
        return resp

    # POST, PUT, DELETE, PATCH all reach here — full bypass
    resp = make_response(
        f"Admin action executed via {method}. Flag: {FLAG}", 200
    )
    resp.headers["X-Method-Used"] = method
    return resp


# =====================================================================
# TARGET 2: /file
# Flawed logic: filter only applied to POST form data. GET is unfiltered.
# PUT/DELETE/PATCH are handled separately and reveal a "write" mode
# that has NO filter at all.
# =====================================================================
@app.route("/file", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def file_lookup():
    method = request.method

    if method == "OPTIONS":
        resp = make_response("", 204)
        resp.headers["Allow"] = "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS"
        return resp

    if method == "POST":
        filename = request.form.get("filename", "")
        if any(bad in filename for bad in ["..", "/", "etc", "passwd"]):
            return "Malicious Request Denied! (POST filter)", 403
        return f"POST lookup of: {filename}"

    if method == "GET":
        # NO filter on query string — the bypass
        filename = request.args.get("filename", "")
        if "passwd" in filename or "etc" in filename:
            return (
                f"GET bypass successful. Flag: {SECOND_FLAG}\n\n"
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin"
            )
        return f"GET lookup of: {filename}"

    if method in ("PUT", "PATCH"):
        # A "write" endpoint that forgot input validation entirely
        body = request.get_data(as_text=True)
        return (
            f"{method} write accepted with no validation.\n"
            f"Body received: {body}\n"
            f"Flag: {SECOND_FLAG}"
        )

    if method == "DELETE":
        # Destructive method, no auth check
        return (
            "DELETE accepted with no authorization.\n"
            f"Flag: {SECOND_FLAG}"
        )

    if method == "HEAD":
        resp = make_response("", 200)
        resp.headers["X-File-Flag"] = SECOND_FLAG
        return resp

    return "Unhandled method", 405


# =====================================================================
# TARGET 3: /trace
# Explicit TRACE echo endpoint. Mirrors request headers back to caller.
# Real-world TRACE is often disabled; when enabled it leaks auth headers,
# cookies, and internal proxy routing info (Cross-Site Tracing / XST).
# =====================================================================
@app.route("/trace", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"])
def trace_endpoint():
    if request.method == "OPTIONS":
        resp = make_response("", 204)
        resp.headers["Allow"] = "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE"
        return resp

    if request.method == "TRACE":
        # Echo back the raw request line and headers — classic TRACE behavior
        echoed = [f"{request.method} {request.path} {request.environ.get('SERVER_PROTOCOL', 'HTTP/1.1')}"]
        for k, v in request.headers.items():
            echoed.append(f"{k}: {v}")
        body = "\n".join(echoed)
        resp = make_response(body, 200)
        resp.headers["X-Trace-Flag"] = THIRD_FLAG
        resp.headers["Content-Type"] = "message/http"
        return resp

    if request.method == "HEAD":
        resp = make_response("", 200)
        resp.headers["X-Trace-Flag"] = THIRD_FLAG
        return resp

    return f"TRACE endpoint reached via {request.method}. Send TRACE to echo headers.", 200


# =====================================================================
# Index
# =====================================================================
@app.route("/")
def index():
    return render_template("index.html")


# Flask does NOT route TRACE by default in older versions.
# Force-allow it on the werkzeug server for teaching purposes.
from werkzeug.serving import WSGIRequestHandler
WSGIRequestHandler.protocol_version = "HTTP/1.1"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
