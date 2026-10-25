import ssl, http.server, socketserver

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        print("REQ", self.headers.get("Host"), self.path, flush=True)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("cert.pem", "key.pem")
srv = socketserver.TCPServer(("127.0.0.1", 8443), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print("listening", flush=True)
srv.serve_forever()
