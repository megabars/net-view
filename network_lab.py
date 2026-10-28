#!/usr/bin/env python3
"""Local, identifiable HTTP/TCP/UDP traffic for testing a packet inspector."""

import argparse
import hashlib
import http.client
import json
import os
import queue
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "127.0.0.1"
MAX_BODY = 1024 * 1024
TIMEOUT = 5
SCENARIOS = ("http", "http-large", "tcp", "udp")
PAGE = """<!doctype html><html lang="ru"><meta charset="utf-8">
<title>Net View — тест браузера</title><body>
<h1>Net View: локальный HTTP-запрос</h1>
<p>Маркер ответа: <strong>NET-VIEW-BROWSER-RESPONSE</strong></p>
<p>Этот запрос отправил браузер. Кнопки настольного приложения отправляют
запросы из отдельного процесса Python.</p>
<p>Обновите страницу, чтобы повторить запрос. Адрес сервера — 127.0.0.1.</p>
</body></html>""".encode("utf-8")


def read_exact(connection, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("Соединение закрыто до получения всех данных")
        chunks.extend(chunk)
    return bytes(chunks)


class HTTPHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(TIMEOUT)

    def log_message(self, *args):
        pass

    def respond(self, status, body, content_type="application/json; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Net-View-Lab", "NET-VIEW-TEST")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self.respond(200, PAGE, "text/html; charset=utf-8")
        elif self.path == "/health":
            self.respond(200, json.dumps({"status": "ok", "server_pid": os.getpid()}).encode())
        else:
            self.respond(404, b'{"error":"not found"}')

    def do_POST(self):
        if self.path != "/echo":
            self.respond(404, b'{"error":"not found"}')
            return
        try:
            size = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            size = -1
        if not 0 <= size <= MAX_BODY:
            self.respond(400, b'{"error":"invalid content length"}')
            return
        try:
            body = self.rfile.read(size)
        except TimeoutError:
            self.respond(408, b'{"error":"read timeout"}')
            return
        if len(body) != size:
            self.respond(400, b'{"error":"incomplete body"}')
            return
        self.respond(200, body)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(TIMEOUT)
        try:
            size = struct.unpack("!I", read_exact(self.request, 4))[0]
            if size > MAX_BODY:
                return
            body = read_exact(self.request, size)
            self.request.sendall(struct.pack("!I", len(body)) + body)
        except (OSError, ConnectionError):
            pass


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        body, connection = self.request
        connection.sendto(body, self.client_address)


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPServer(socketserver.UDPServer):
    max_packet_size = 65535


def serve(args):
    servers = []
    try:
        # Bind everything before reporting readiness; a port conflict is fatal.
        servers.append(ThreadingHTTPServer((HOST, args.http_port), HTTPHandler))
        servers.append(TCPServer((HOST, args.tcp_port), TCPHandler))
        servers.append(UDPServer((HOST, args.udp_port), UDPHandler))
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        print(json.dumps({"ready": True, "pid": os.getpid(),
                          **{f"{name}_port": server.server_address[1]
                             for name, server in zip(("http", "tcp", "udp"), servers)}}), flush=True)
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.server_close()


def exchange(scenario, ports):
    protocol = "http" if scenario.startswith("http") else scenario
    port = ports[f"{protocol}_port"]
    payload = {
        "marker": "NET-VIEW-TEST",
        "request_id": str(uuid.uuid4()),
        "client_pid": os.getpid(),
        "scenario": scenario,
        "message": "Привет, сеть! Проверяем отправку и получение данных.",
    }
    if scenario == "http-large":
        payload["data"] = "0123456789ABCDEF" * 4096
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    started = time.monotonic()
    if protocol == "http":
        connection = http.client.HTTPConnection(HOST, port, timeout=TIMEOUT)
        try:
            connection.request("POST", "/echo", body=body,
                               headers={"Content-Type": "application/json; charset=utf-8",
                                        "X-Net-View-Request": payload["request_id"]})
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status}: {response.reason}")
            received = response.read(MAX_BODY + 1)
        finally:
            connection.close()
    elif protocol == "tcp":
        with socket.create_connection((HOST, port), timeout=TIMEOUT) as connection:
            connection.sendall(struct.pack("!I", len(body)) + body)
            size = struct.unpack("!I", read_exact(connection, 4))[0]
            if size > MAX_BODY:
                raise ValueError("Слишком большой ответ TCP")
            received = read_exact(connection, size)
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(TIMEOUT)
            connection.connect((HOST, port))
            connection.send(body)
            received = connection.recv(65535)
    return {
        "scenario": scenario, "protocol": protocol.upper(),
        "client_pid": os.getpid(), "address": f"{HOST}:{port}",
        "request_id": payload["request_id"],
        "sent_bytes": len(body), "received_bytes": len(received),
        "sha256": hashlib.sha256(body).hexdigest(),
        "received_sha256": hashlib.sha256(received).hexdigest(),
        "matched": body == received,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
        "preview": body.decode("utf-8")[:700],
        "received_preview": received.decode("utf-8", errors="replace")[:700],
    }


def stop_child(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
    if child.stdout:
        child.stdout.close()


def start_child(args):
    command = [sys.executable, str(Path(__file__).resolve()), "server"]
    for name in ("http", "tcp", "udp"):
        command.extend([f"--{name}-port", str(getattr(args, f"{name}_port"))])
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, encoding="utf-8")
    ready = queue.Queue()
    threading.Thread(target=lambda: ready.put(child.stdout.readline()), daemon=True).start()
    try:
        line = ready.get(timeout=TIMEOUT)
        metadata = json.loads(line)
        if not metadata.get("ready"):
            raise ValueError("Сервер не подтвердил запуск")
        return child, metadata
    except (queue.Empty, ValueError) as error:
        stop_child(child)
        raise RuntimeError("Не удалось запустить сервер. Возможно, тестовые порты заняты. "
                           "Попробуйте --http-port 0 --tcp-port 0 --udp-port 0.") from error


def gui(args):
    import tkinter as tk
    from tkinter import messagebox, scrolledtext, ttk

    root = tk.Tk()
    root.title("Net View — тестовое приложение")
    root.geometry("960x740")
    root.minsize(760, 580)
    child = None
    ports = vars(args).copy()
    try:
        if not args.connect:
            child, ports = start_child(args)
    except RuntimeError as error:
        messagebox.showerror("Не удалось запустить тестовый сервер", str(error))
        root.destroy()
        return 1

    container = ttk.Frame(root, padding=20)
    container.pack(fill="both", expand=True)
    ttk.Label(container, text="Сетевая лаборатория", font=("Helvetica", 22, "bold")).pack(anchor="w")
    ttk.Label(container, text="Известные сообщения для проверки захвата и сборки пакетов.").pack(anchor="w", pady=(6, 12))
    server_pid = ports.get("pid", "внешний сервер")
    ttk.Label(container, text=f"Клиент: Python, PID {os.getpid()}     •     Сервер: PID {server_pid}").pack(anchor="w")
    ttk.Label(container, text="     ".join(f"{p.upper()}: {HOST}:{ports[p + '_port']}" for p in ("http", "tcp", "udp"))).pack(anchor="w", pady=(4, 12))
    ttk.Label(container, text="Трафик остаётся на этом компьютере. Для захвата на macOS используйте lo0.").pack(anchor="w")
    ttk.Label(container, text="HTTP без шифрования. TCP: длина (4 байта) + JSON. UDP: одна датаграмма с JSON.").pack(anchor="w", pady=(4, 12))

    controls = ttk.Frame(container)
    controls.pack(fill="x", pady=(0, 8))
    status = tk.StringVar(value="Готово. Нажмите кнопку, чтобы отправить данные.")
    buttons = []
    results = queue.Queue()
    log = scrolledtext.ScrolledText(container, wrap="word", font=("Menlo", 11), state="disabled")

    def append(message):
        log.configure(state="normal")
        log.insert("end", message + "\n\n")
        # Keep a bounded UI history during repeated testing.
        lines = int(log.index("end-1c").split(".")[0])
        if lines > 1500:
            log.delete("1.0", f"{lines - 1200}.0")
        log.see("end")
        log.configure(state="disabled")

    def work(scenarios):
        try:
            for scenario in scenarios:
                results.put(("result", exchange(scenario, ports)))
        except Exception as error:
            results.put(("error", str(error)))
        finally:
            results.put(("done", None))

    def run(scenario):
        for button in buttons:
            button.configure(state="disabled")
        status.set("Отправка и проверка ответа…")
        threading.Thread(target=work, args=(SCENARIOS if scenario == "all" else (scenario,),), daemon=True).start()

    for label, scenario in (("HTTP · JSON", "http"), ("HTTP · 64 КиБ+", "http-large"),
                            ("TCP · JSON", "tcp"), ("UDP · JSON", "udp"), ("Все сценарии", "all")):
        button = ttk.Button(controls, text=label, command=lambda s=scenario: run(s))
        button.pack(side="left", padx=(0, 8))
        buttons.append(button)

    extras = ttk.Frame(container)
    extras.pack(fill="x", pady=(0, 10))
    ttk.Button(extras, text="Открыть страницу в браузере", command=lambda: webbrowser.open(f"http://{HOST}:{ports['http_port']}/")).pack(side="left")
    ttk.Label(extras, text="Запрос страницы будет принадлежать браузеру.").pack(side="left", padx=12)
    ttk.Label(container, textvariable=status).pack(anchor="w", pady=(0, 8))
    log.pack(fill="both", expand=True)
    append("Маркер в сообщениях: NET-VIEW-TEST\nРазмеры ниже — байты полезных данных, без заголовков протоколов.\n"
           "Число пакетов зависит от сетевого стека. Для большого сообщения показаны первые 700 символов.")

    def poll():
        try:
            while True:
                kind, value = results.get_nowait()
                if kind == "result":
                    append(f"{'✓ Совпадает' if value['matched'] else '✗ Различается'} · {value['scenario']} → {value['address']}\n"
                           f"Отправлено: {value['sent_bytes']} байт · Получено: {value['received_bytes']} байт · {value['elapsed_ms']} мс\n"
                           f"SHA-256 отправки: {value['sha256']}\nSHA-256 ответа: {value['received_sha256']}\n"
                           f"Отправка: {value['preview']}\nОтвет: {value['received_preview']}")
                elif kind == "error":
                    append(f"Ошибка: {value}")
                elif kind == "done":
                    status.set("Проверка завершена. Результаты ниже.")
                    for button in buttons:
                        button.configure(state="normal")
        except queue.Empty:
            pass
        root.after(100, poll)

    root.after(100, poll)
    try:
        root.mainloop()
    finally:
        if child:
            stop_child(child)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", nargs="?", choices=("gui", "server", "client"), default="gui")
    parser.add_argument("--http-port", type=int, default=18765)
    parser.add_argument("--tcp-port", type=int, default=18766)
    parser.add_argument("--udp-port", type=int, default=18767)
    parser.add_argument("--scenario", choices=(*SCENARIOS, "all"), default="all")
    parser.add_argument("--connect", action="store_true", help="GUI: use an already running server")
    args = parser.parse_args()
    for name in ("http", "tcp", "udp"):
        port = getattr(args, f"{name}_port")
        if not 0 <= port <= 65535:
            parser.error("Порт должен быть в диапазоне 0–65535")
        if port == 0 and (args.mode == "client" or args.connect):
            parser.error("Для подключения укажите фактические порты сервера, а не 0")
    try:
        if args.mode == "server":
            serve(args)
        elif args.mode == "client":
            results = [exchange(scenario, vars(args)) for scenario in
                       (SCENARIOS if args.scenario == "all" else (args.scenario,))]
            print(json.dumps(results, ensure_ascii=False, indent=2))
            return 0 if all(result["matched"] for result in results) else 1
        else:
            return gui(args)
    except (OSError, RuntimeError, ImportError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
