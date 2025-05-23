from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import pty
import select
import signal
import logging
import time

# ⚙️ Configuração do logger
logging.basicConfig(
    filename='server.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

shells = {}

def start_shell(uid):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("bash", ["bash"])
    else:
        shells[uid] = (pid, fd)

def stop_shell(uid):
    if uid in shells:
        pid, fd = shells.pop(uid)
        os.kill(pid, signal.SIGKILL)
        os.close(fd)

def send_command(uid, cmd):
    if uid not in shells:
        start_shell(uid)
        time.sleep(1)  # Give the shell time to start

    pid, fd = shells[uid]
    os.write(fd, cmd.encode() + b'\n')

    output = b''
    while True:
        r, _, _ = select.select([fd], [], [], 0.3)
        if fd in r:
            try:
                chunk = os.read(fd, 1024)
                if not chunk:
                    break
                output += chunk
            except OSError:
                break
        else:
            break

    decoded = output.decode(errors='ignore')
    lines = decoded.splitlines()

    cleaned_lines = []
    skip_next = False
    for line in lines:
        if skip_next:
            skip_next = False
            continue
        if line.strip() == cmd.strip():
            skip_next = True
            continue
        cleaned_lines.append(line)

    return '\n'.join(cleaned_lines).rstrip()

class ShellHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_POST(self):
        if self.path != "/execute":
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not Found"}).encode())
            return

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        try:
            data = json.loads(body)
            uid = data.get("uid")
            cmd = data.get("cmd")

            if not uid or not cmd:
                raise ValueError("Missing uid or cmd")

            # 📌 Log de requisição
            logging.info(f"UID={uid} | CMD='{cmd}'")

            if cmd.strip().lower() == "exit":
                stop_shell(uid)
                self._set_headers()
                self.wfile.write(json.dumps({"message": "Shell terminated"}).encode())
                return

            output = send_command(uid, cmd)
            self._set_headers()
            self.wfile.write(json.dumps({"output": output}).encode())

        except Exception as e:
            logging.error(f"Erro do cliente {uid}: {e}")
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": str(e)}).encode())

def run():
    server_address = ('0.0.0.0', 8000)
    httpd = HTTPServer(server_address, ShellHandler)
    print("Servidor HTTP disponível em http://0.0.0.0:8000")
    logging.info("Servidor iniciado.")
    httpd.serve_forever()

if __name__ == "__main__":
    run()