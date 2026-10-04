from flask import Flask, request, render_template, make_response, jsonify

app = Flask(__name__)

METHOD_INFO = {
    "GET": {
        "purpose": "Retrieve a representation of the resource.",
        "safe": True, "idempotent": True, "body": "No",
        "typical_use": "Loading pages, fetching data, filtering via query string.",
        "attack_surface": "Query strings logged in access logs, browser history, Referer. Never put secrets in ?key=value.",
    },
    "POST": {
        "purpose": "Submit data to be processed.",
        "safe": False, "idempotent": False, "body": "Yes",
        "typical_use": "Login forms, file uploads, creating records.",
        "attack_surface": "Assumed CSRF-protected. Often overlooked when devs only guard GET.",
    },
    "PUT": {
        "purpose": "Replace the entire resource at the URI.",
        "safe": False, "idempotent": True, "body": "Yes",
        "typical_use": "Upload file to known URI, full record replace.",
        "attack_surface": "Missing auth on PUT = overwrite anyone's data.",
    },
    "PATCH": {
        "purpose": "Apply partial modifications to a resource.",
        "safe": False, "idempotent": False, "body": "Yes",
        "typical_use": "Update one field, toggle a flag.",
        "attack_surface": "Mass assignment — sending fields the dev forgot to whitelist.",
    },
    "DELETE": {
        "purpose": "Remove the resource.",
        "safe": False, "idempotent": True, "body": "Rarely",
        "typical_use": "Delete records, revoke tokens.",
        "attack_surface": "Often excluded from CSRF protection. Cookies alone can trigger it.",
    },
    "HEAD": {
        "purpose": "Identical to GET but no response body.",
        "safe": True, "idempotent": True, "body": "No",
        "typical_use": "Metadata checks, link validators, CDN freshness.",
        "attack_surface": "Handler runs, body stripped. Leaks only via headers. Auth checks that test == 'GET' miss it.",
    },
    "OPTIONS": {
        "purpose": "Report which methods the target supports.",
        "safe": True, "idempotent": True, "body": "No",
        "typical_use": "CORS preflight, API discovery.",
        "attack_surface": "Unauthenticated recon — reveals attack surface.",
    },
    "TRACE": {
        "purpose": "Echo the received request back to the client.",
        "safe": True, "idempotent": True, "body": "Echo",
        "typical_use": "Debugging proxy chains. Should be disabled.",
        "attack_surface": "Cross-Site Tracing (XST) — steals HttpOnly cookies via XSS.",
    },
    "CONNECT": {
        "purpose": "Establish a TCP tunnel to another host.",
        "safe": False, "idempotent": False, "body": "No",
        "typical_use": "HTTPS through an HTTP proxy.",
        "attack_surface": "Open CONNECT relays enable proxy pivoting.",
    },
}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/methods")
def methods():
    return jsonify(METHOD_INFO)


# ---------- Demo endpoints ----------

@app.route("/demo/get", methods=["GET"])
def demo_get():
    return _echo("GET", {
        "query_params": dict(request.args),
        "interesting_headers": _interesting_headers(),
    })


@app.route("/demo/post", methods=["POST"])
def demo_post():
    return _echo("POST", {
        "form_data": dict(request.form),
        "json_body": request.get_json(silent=True),
        "raw_body": request.get_data(as_text=True),
        "content_type": request.content_type,
    })


@app.route("/demo/put", methods=["PUT"])
def demo_put():
    return _echo("PUT", {
        "raw_body": request.get_data(as_text=True),
        "note": "PUT semantically means REPLACE the whole resource.",
    })


@app.route("/demo/patch", methods=["PATCH"])
def demo_patch():
    return _echo("PATCH", {
        "raw_body": request.get_data(as_text=True),
        "note": "PATCH semantically means apply a PARTIAL update.",
    })


@app.route("/demo/delete", methods=["DELETE"])
def demo_delete():
    return _echo("DELETE", {
        "note": "DELETE removed a resource (simulated).",
        "would_delete_id": request.args.get("id", "<unspecified>"),
    })


@app.route("/demo/head", methods=["HEAD"])
def demo_head():
    resp = make_response("", 200)
    resp.headers["X-Method-Reached"] = "HEAD"
    resp.headers["X-This-Would-Be-Body"] = "If this were GET, this would be the body content"
    resp.headers["X-Auth-Check-Note"] = "Handlers that only block GET miss this entirely"
    return resp


@app.route("/demo/options", methods=["OPTIONS"])
def demo_options():
    resp = make_response("", 204)
    resp.headers["Allow"] = "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS"
    return resp


@app.route("/demo/trace", methods=["TRACE"])
def demo_trace():
    echoed = [f"{request.method} {request.path} {request.environ.get('SERVER_PROTOCOL', 'HTTP/1.1')}"]
    for k, v in request.headers.items():
        echoed.append(f"{k}: {v}")
    resp = make_response("\n".join(echoed), 200)
    resp.headers["Content-Type"] = "message/http"
    return resp


# ---------- Vulnerable demo endpoint ----------

@app.route("/vuln/admin", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def vuln_admin():
    m = request.method
    if m == "GET":
        return make_response(jsonify({
            "error": "Access denied",
            "reason": "GET is blocked by the 'security check'",
        }), 401)

    if m == "OPTIONS":
        r = make_response("", 204)
        r.headers["Allow"] = "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS"
        return r

    if m == "HEAD":
        r = make_response("", 200)
        r.headers["X-Admin-Secret"] = "TUTORIAL{HEAD_BYPASSES_GET_CHECK}"
        return r

    return jsonify({
        "status": "bypassed",
        "method_used": m,
        "lesson": f"The dev only blocked GET. {m} slid right through.",
        "tutorial_flag": "TUTORIAL{METHOD_CHECK_BYPASS}",
    })


# ---------- helpers ----------

def _echo(method, payload):
    payload["_method_reached"] = method
    payload["_client_ip"] = request.remote_addr
    payload["_user_agent"] = request.headers.get("User-Agent")
    return jsonify(payload)


def _interesting_headers():
    keys = ["Authorization", "Cookie", "Referer", "X-Forwarded-For", "X-HTTP-Method-Override"]
    return {k: request.headers.get(k) for k in keys if request.headers.get(k)}


import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
