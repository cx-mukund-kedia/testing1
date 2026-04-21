# xss_vulnerable_routes.py
# Drop this file into the same directory and import it from your server.

from urllib.parse import urlparse, parse_qs
import html as html_lib

STORED_COMMENTS = []
STORED_MESSAGES = []
USER_PROFILES   = {"alice": "Alice Smith", "bob": "Bob Jones"}

def handle_xss_routes(handler):
    """
    Call this from your Handler.do_GET().
    Returns True if the route was handled, False otherwise.

    Usage in server.py:
        from xss_vulnerable_routes import handle_xss_routes

        def do_GET(self):
            if handle_xss_routes(self):
                return
            # ... your existing routes
    """
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
# Attack: /xss/search?q=<script>alert(1)</script>

def _search(handler, params):
    query = params.get("q", [""])[0]

    # ❌ Raw input echoed into page body and into an input's value attribute
    html = f"""<!DOCTYPE html><html><head><title>Search</title></head><body>
    <h2>Search</h2>
    <form method="GET" action="/xss/search">
        <input name="q" value="{query}">
        <button>Search</button>
    </form>
    <p>Results for: {query}</p>
    <p>Try the other routes: /xss/profile  /xss/comment  /xss/redirect  /xss/template  /xss/json</p>
    </body></html>"""
    _send(handler, html)


# ── 2. Attribute breakout ─────────────────────────────────────────────────────
# Attack: /xss/profile?user=" onmouseover="alert(document.cookie)

def _profile(handler, params):
    username    = params.get("user", ["guest"])[0]
    displayname = USER_PROFILES.get(username, username)

    # ❌ username lands inside an HTML attribute unquoted — close it with "
    # ❌ displayname reflected in body without escaping
    html = f"""<!DOCTYPE html><html><head><title>Profile</title></head><body>
    <div class="card" data-user="{username}">
        <h2>{displayname}</h2>
        <p>Logged in as: {username}</p>
    </div>
    </body></html>"""
    _send(handler, html)


# ── 3. Stored XSS ─────────────────────────────────────────────────────────────
# Attack: /xss/comment?text=<img src=x onerror=alert('stored')>
# Then reload /xss/comment — payload fires for every visitor.

def _comment(handler, params):
    text = params.get("text", [None])[0]
    if text:
        STORED_COMMENTS.append(text)

    # ❌ Every stored comment injected raw — affects ALL future visitors
    items = "".join(f"<li>{c}</li>" for c in STORED_COMMENTS)

    html = f"""<!DOCTYPE html><html><head><title>Comments</title></head><body>
    <h2>Comments</h2>
    <form method="GET" action="/xss/comment">
        <input name="text" placeholder="Leave a comment" style="width:300px">
        <button>Post</button>
    </form>
    <ul>{items or "<li>No comments yet.</li>"}</ul>
    </body></html>"""
    _send(handler, html)


# ── 4. Open redirect + DOM XSS via javascript: URI ───────────────────────────
# Attack: /xss/redirect?to=javascript:alert(document.cookie)
# The href becomes a live JS execution context — no <script> tag needed.

def _redirect(handler, params):
    destination = params.get("to", ["/"])[0]

    # ❌ Destination placed directly into an href — javascript: URIs execute
    html = f"""<!DOCTYPE html><html><head><title>Redirect</title></head><body>
    <h2>Click to continue</h2>
    <a href="{destination}">Proceed →</a>
    </body></html>"""
    _send(handler, html)


# ── 5. Server-side template injection style ───────────────────────────────────
# Attack: /xss/template?name=<h1>Injected</h1><script>alert(5)</script>
# The greeting wraps user input in markup, amplifying the injection surface.

def _template(handler, params):
    name    = params.get("name", ["stranger"])[0]
    subject = params.get("subject", ["the weather"])[0]

    # ❌ Both params inserted raw; attacker controls tag structure of the page
    html = f"""<!DOCTYPE html><html><head><title>Greeting</title></head><body>
    <div class="greeting">
        <h2>Hello, {name}!</h2>
        <p>Today we are talking about {subject}.</p>
    </div>
    <form method="GET" action="/xss/template">
        <input name="name"    placeholder="Your name"   value="{name}">
        <input name="subject" placeholder="Topic"       value="{subject}">
        <button>Update</button>
    </form>
    </body></html>"""
    _send(handler, html)


# ── 6. JSON reflected into a <script> block ───────────────────────────────────
# Attack: /xss/json?callback=alert(1)//
# The server wraps user input in JS — classic JSONP-style injection.

def _json_reflected(handler, params):
    callback = params.get("callback", ["handleData"])[0]
    data     = '{"status": "ok", "value": 42}'

    # ❌ callback name injected directly into a <script> block
    html = f"""<!DOCTYPE html><html><head><title>JSON</title></head>
    <script>
        var data = {data};
        {callback}(data);   // attacker controls this identifier
    </script>
    <body><p>Check the browser console.</p></body></html>"""
    _send(handler, html)


# ── helpers ───────────────────────────────────────────────────────────────────

def _send(handler, html: str, status: int = 200):
    encoded = html.strip().encode("utf-8")
    handler.send_response(status)
    # ❌ No Content-Security-Policy header — browser will execute anything
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(encoded)))
    handler.end_headers()
    handler.wfile.write(encoded)
