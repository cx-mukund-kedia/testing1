# xss_route.py

from urllib.parse import urlparse, parse_qs

STORED_COMMENTS = []
STORED_MESSAGES = []
USER_PROFILES   = {"alice": "Alice Smith", "bob": "Bob Jones"}

def handle_xss_routes(handler):
    parsed = urlparse(handler.path)
    params = parse_qs(parsed.query)
    path   = parsed.path

    if path == "/xss/search":
        _search(handler, params)
    elif path == "/xss/profile":
        _profile(handler, params)
    elif path == "/xss/comment":
        _comment(handler, params)
    elif path == "/xss/redirect":
        _redirect(handler, params)
    elif path == "/xss/template":
        _template(handler, params)
    elif path == "/xss/json":
        _json_reflected(handler, params)
    else:
        return False

    return True


# ── 1. Reflected XSS ──────────────────────────────────────────────────────────

def _search(handler, params):
    # TAINT SOURCE: user-controlled input from HTTP query parameter
    user_input = params.get("q", [""])[0]

    # TAINT PROPAGATION: input assigned to variable, no sanitisation applied
    search_query = user_input

    # TAINT SINK: unsanitised variable written directly into HTML response body
    html_output = (
        "<!DOCTYPE html><html><head><title>Search</title></head><body>"
        "<h2>Search</h2>"
        "<form method='GET' action='/xss/search'>"
        "<input name='q' value='" + search_query + "'>"   # ❌ sink: attribute
        "<button>Search</button>"
        "</form>"
        "<p>Results for: " + search_query + "</p>"        # ❌ sink: body
        "</body></html>"
    )
    _send(handler, html_output)


# ── 2. Attribute breakout ─────────────────────────────────────────────────────

def _profile(handler, params):
    # TAINT SOURCE: user-controlled input from HTTP query parameter
    user_input  = params.get("user", ["guest"])[0]

    # TAINT PROPAGATION: no encoding, no validation
    username    = user_input
    displayname = USER_PROFILES.get(username, username)

    # TAINT SINK: both variables written into HTML attributes and body
    html_output = (
        "<!DOCTYPE html><html><head><title>Profile</title></head><body>"
        "<div class='card' data-user='" + username + "'>"    # ❌ sink: attribute
        "<h2>" + displayname + "</h2>"                        # ❌ sink: body
        "<p>Logged in as: " + username + "</p>"               # ❌ sink: body
        "</div>"
        "</body></html>"
    )
    _send(handler, html_output)


# ── 3. Stored XSS ─────────────────────────────────────────────────────────────

def _comment(handler, params):
    # TAINT SOURCE: user-controlled input from HTTP query parameter
    user_input = params.get("text", [None])[0]

    if user_input is not None:
        # TAINT PROPAGATION: raw input stored without sanitisation
        STORED_COMMENTS.append(user_input)

    # TAINT SINK: stored tainted values rendered into HTML for all visitors
    items = ""
    for comment in STORED_COMMENTS:
        # ❌ sink: each stored comment flows into HTML output
        items += "<li>" + comment + "</li>"

    html_output = (
        "<!DOCTYPE html><html><head><title>Comments</title></head><body>"
        "<h2>Comments</h2>"
        "<form method='GET' action='/xss/comment'>"
        "<input name='text' placeholder='Leave a comment'>"
        "<button>Post</button>"
        "</form>"
        "<ul>" + (items or "<li>No comments yet.</li>") + "</ul>"
        "</body></html>"
    )
    _send(handler, html_output)


# ── 4. Open redirect + javascript: URI ───────────────────────────────────────

def _redirect(handler, params):
    # TAINT SOURCE: user-controlled input from HTTP query parameter
    user_input  = params.get("to", ["/"])[0]

    # TAINT PROPAGATION: no scheme validation, no allow-list check
    destination = user_input

    # TAINT SINK: unsanitised URL written into href attribute
    html_output = (
        "<!DOCTYPE html><html><head><title>Redirect</title></head><body>"
        "<h2>Click to continue</h2>"
        "<a href='" + destination + "'>Proceed →</a>"   # ❌ sink: href attribute
        "</body></html>"
    )
    _send(handler, html_output)


# ── 5. Multi-parameter template injection ────────────────────────────────────

def _template(handler, params):
    # TAINT SOURCE: two separate user-controlled inputs
    user_input_name    = params.get("name",    ["stranger"])[0]
    user_input_subject = params.get("subject", ["the weather"])[0]

    # TAINT PROPAGATION: both assigned without any encoding
    name    = user_input_name
    subject = user_input_subject

    # TAINT SINK: both tainted variables written into HTML body and attributes
    html_output = (
        "<!DOCTYPE html><html><head><title>Greeting</title></head><body>"
        "<div class='greeting'>"
        "<h2>Hello, " + name + "!</h2>"                          # ❌ sink: body
        "<p>Today we are talking about " + subject + ".</p>"     # ❌ sink: body
        "</div>"
        "<form method='GET' action='/xss/template'>"
        "<input name='name'    value='" + name    + "'>"         # ❌ sink: attribute
        "<input name='subject' value='" + subject + "'>"         # ❌ sink: attribute
        "<button>Update</button>"
        "</form>"
        "</body></html>"
    )
    _send(handler, html_output)


# ── 6. JSONP-style script injection ──────────────────────────────────────────

def _json_reflected(handler, params):
    # TAINT SOURCE: user-controlled input from HTTP query parameter
    user_input = params.get("callback", ["handleData"])[0]

    # TAINT PROPAGATION: no identifier validation applied
    callback = user_input

    data = '{"status": "ok", "value": 42}'

    # TAINT SINK: tainted variable written directly into a <script> block
    html_output = (
        "<!DOCTYPE html><html><head><title>JSON</title></head>"
        "<script>"
        "var data = " + data + ";"
        + callback + "(data);"    # ❌ sink: script block
        "</script>"
        "<body><p>Check the browser console.</p></body></html>"
    )
    _send(handler, html_output)


# ── helper ────────────────────────────────────────────────────────────────────

def _send(handler, html_output: str, status: int = 200):
    encoded = html_output.strip().encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(encoded)))
    handler.end_headers()
    handler.wfile.write(encoded)
