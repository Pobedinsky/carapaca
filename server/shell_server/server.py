"""
Shell Execution Server

This server provides a secure interface for executing shell commands via HTTP.
It maintains isolated shell sessions for each user and handles command execution
and output capture securely.

The server is a backend component for the Carapaca secure shell system, receiving
commands from the main Rust server which handles the cryptographic operations.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import pty           # For creating pseudo terminals
import select        # For I/O multiplexing
import signal        # For process control
import logging
import time

# Configure logging for server operations
logging.basicConfig(
    filename='server.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Dictionary to store active shell sessions (user_id -> (pid, file_descriptor))
shells = {}

def start_shell(uid):
    """
    Start a new shell process for a user
    
    Creates a pseudo-terminal and spawns a bash shell process,
    then stores the process ID and file descriptor for future use.
    
    Args:
        uid (str): User identifier for the shell session
    """
    pid, fd = pty.fork()
    if pid == 0:
        # Child process: replace with bash shell
        os.execvp("bash", ["bash"])
    else:
        # Parent process: store the shell info
        shells[uid] = (pid, fd)

def stop_shell(uid):
    """
    Stop a user's shell process
    
    Terminates the shell process and cleans up resources.
    
    Args:
        uid (str): User identifier for the shell session
    """
    if uid in shells:
        pid, fd = shells.pop(uid)
        os.kill(pid, signal.SIGKILL)  # Forcefully terminate the process
        os.close(fd)                  # Close the file descriptor

def send_command(uid, cmd):
    """
    Send a command to a user's shell and capture the output
    
    Creates a shell if one doesn't exist for the user, sends the command,
    and captures the output with appropriate formatting.
    
    Args:
        uid (str): User identifier for the shell session
        cmd (str): Command to execute
        
    Returns:
        str: Command output
    """
    # Create a shell if one doesn't exist for this user
    if uid not in shells:
        start_shell(uid)
        time.sleep(1)  # Allow time for the shell to initialize

    # Get the shell process information
    pid, fd = shells[uid]
    
    # Send the command to the shell
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