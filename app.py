# server.py
from http.server import BaseHTTPRequestHandler, HTTPServer
from xss_vulnerable_routes import handle_xss_routes

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        if handle_xss_routes(self):
            return

        if self.path == "/" or self.path == "/index.html":
            html = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Home</title>
                <style>
                    body { font-family: sans-serif; max-width: 600px; margin: 80px auto; padding: 0 20px; color: #333; }
                    h1   { font-size: 2rem; margin-bottom: 8px; }
                    p    { color: #666; line-height: 1.6; }
                    a    { color: #0070f3; text-decoration: none; }
                    a:hover { text-decoration: underline; }
                    ul   { padding-left: 20px; }
                    li   { margin: 6px 0; }
                </style>
            </head>
            <body>
                <h1>Welcome home 👋</h1>
                <p>This is a simple Python HTTP server with no external dependencies.</p>
                <p><a href="/about">About</a></p>
                <hr>
                <h2>XSS Demo Routes</h2>
                <ul>
                    <li><a href='/xss/search?q=hello'>Reflected XSS — search</a></li>
                    <li><a href='/xss/profile?user=alice'>Attribute breakout — profile</a></li>
                    <li><a href='/xss/comment'>Stored XSS — comments</a></li>
                    <li><a href='/xss/redirect?to=/'>Open redirect + javascript: URI</a></li>
                    <li><a href='/xss/template?name=stranger&subject=security'>Template injection</a></li>
                    <li><a href='/xss/json?callback=handleData'>JSONP-style script injection</a></li>
                </ul>
            </body>
            </html>
            """
            self._send(200, html)

        elif self.path == "/about":
            html = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>About</title>
                <style>
                    body { font-family: sans-serif; max-width: 600px; margin: 80px auto; padding: 0 20px; color: #333; }
                    a    { color: #0070f3; }
                </style>
            </head>
            <body>
                <h1>About</h1>
                <p>Built with nothing but the Python standard library.</p>
                <p><a href="/">← Back home</a></p>
            </body>
            </html>
            """
            self._send(200, html)

        else:
            self._send(404, "<h1>404 — Page not found</h1>")

    def _send(self, status: int, html: str):
        encoded = html.strip().encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        print(f"{args[1]} {args[0]}")


if __name__ == "__main__":
    server = HTTPServer(("", 8080), Handler)
    print("Serving at http://localhost:8080")
    server.serve_forever()
