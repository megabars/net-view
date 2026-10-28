"""Small native desktop UI. All traffic work stays off the Tk thread."""

import json
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from .capture import CaptureService, list_processes, parse_pcapng
from .session import Session

ROOT = Path(__file__).resolve().parents[1]
PREVIEW_LIMIT = 256 * 1024


def format_size(size):
    if size >= 1024 * 1024:
        return f"{size / 1024 / 1024:.1f} МиБ"
    if size >= 1024:
        return f"{size / 1024:.1f} КиБ"
    return f"{size} Б"


def hex_dump(data):
    data = data[:PREVIEW_LIMIT]
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        text = "".join(chr(value) if 32 <= value < 127 else "." for value in chunk)
        lines.append(f"{offset:06x}  {chunk.hex(' '):47s}  {text}")
    return "\n".join(lines) or "Нет данных."


def readable(data):
    """A display convenience, not an inference of arbitrary application protocols."""
    if not data:
        return "Нет прикладных данных (например, подтверждение TCP)."
    if len(data) >= 3 and data[0] in (20, 21, 22, 23) and data[1] == 3 and data[2] <= 4:
        return ("Данные имеют заголовок TLS. MVP не расшифровывает TLS/HTTPS.\n"
                "Исходные байты доступны во вкладке HEX; адреса и размеры — в таблицах.")
    note = ""
    if len(data) > PREVIEW_LIMIT:
        note = f"Показаны первые {format_size(PREVIEW_LIMIT)} из {format_size(len(data))}.\n\n"
    prefix = data[:PREVIEW_LIMIT]
    if len(prefix) > 4 and int.from_bytes(prefix[:4], "big") == len(data) - 4:
        prefix = prefix[4:]
        note += "Обнаружен префикс длины 4 байта (формат тестового TCP-клиента).\n\n"
    try:
        text = prefix.decode("utf-8")
    except UnicodeDecodeError:
        return note + "Бинарные данные или неполная последовательность UTF-8. Смотрите HEX."
    if any(not (char.isprintable() or char in "\r\n\t") for char in text):
        return note + "Бинарные данные. Смотрите HEX."
    try:
        return note + json.dumps(json.loads(text), ensure_ascii=False, indent=2)
    except (ValueError, RecursionError):
        pass
    if text.startswith(("HTTP/", "GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ")) and "\r\n\r\n" in text:
        headers, body = text.split("\r\n\r\n", 1)
        try:
            body = json.dumps(json.loads(body), ensure_ascii=False, indent=2)
        except (ValueError, RecursionError):
            pass
        return note + headers.replace("\r\n", "\n") + "\n\n" + body
    return note + text.replace("\r\n", "\n")


class Inspector:
    def __init__(self, root, initial_file=None):
        self.root = root
        self.session = Session()
        self.capture = CaptureService()
        self.background = queue.Queue()
        self.processes = []
        self.selected_pid = None
        self.capture_pid = None
        self.capture_error = None
        self.selected_connection = None
        self.packet_filter = None
        self.dirty = False
        self.stopping = False
        self.dropped = 0
        self.kernel_dropped = None
        self.run_queue_drops = 0
        self.run_kernel_drops = 0
        self.loss_note = None
        self.rendered_packets = 0
        self.last_stream_render = 0
        self.controls_busy = False
        self.process_refreshing = False
        self.closed = False
        self.build()
        self.refresh_processes()
        self.root.after(100, self.poll)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        if initial_file:
            self.root.after(200, lambda: self.open_session(initial_file))

    def build(self):
        root = self.root
        root.title("Net View — сетевой инспектор")
        root.geometry("1320x880")
        root.minsize(1020, 700)
        style = ttk.Style(root)
        style.configure("Treeview", rowheight=25)
        style.configure("Title.TLabel", font=("Helvetica", 23, "bold"))
        style.configure("Section.TLabel", font=("Helvetica", 13, "bold"))
        shell = ttk.Frame(root, padding=16)
        shell.pack(fill="both", expand=True)
        header = ttk.Frame(shell)
        header.pack(fill="x", pady=(0, 12))
        ttk.Label(header, text="Net View", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="Приложение → соединение → пакеты и данные").pack(side="left", padx=20)
        ttk.Button(header, text="Тестовый клиент", command=self.launch_lab).pack(side="right")
        toolbar = ttk.Frame(shell)
        toolbar.pack(fill="x", pady=(0, 8))
        self.start_button = ttk.Button(toolbar, text="▶ Начать захват", command=self.start_capture)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(toolbar, text="■ Остановить", command=self.stop_capture, state="disabled")
        self.stop_button.pack(side="left", padx=8)
        self.open_button = ttk.Button(toolbar, text="Открыть сеанс…", command=self.open_session)
        self.open_button.pack(side="left")
        self.save_button = ttk.Button(toolbar, text="Сохранить…", command=self.save_session)
        self.save_button.pack(side="left", padx=8)
        self.clear_button = ttk.Button(toolbar, text="Очистить", command=self.clear)
        self.clear_button.pack(side="left")
        self.target = tk.StringVar(value="Выберите процесс слева")
        ttk.Label(toolbar, textvariable=self.target).pack(side="right")
        self.status = tk.StringVar(value="Готово. Для захвата нужны права BPF; запуск через Start Net View.command.")
        ttk.Label(shell, textvariable=self.status, wraplength=1240).pack(fill="x", pady=(0, 8))
        footer_panel = ttk.Frame(shell)
        footer_panel.pack(side="bottom", fill="x", pady=(8, 0))

        panels = ttk.Panedwindow(shell, orient="horizontal")
        panels.pack(fill="both", expand=True)
        sidebar = ttk.Frame(panels, padding=(0, 0, 12, 0))
        panels.add(sidebar, weight=1)
        ttk.Label(sidebar, text="Процессы", style="Section.TLabel").pack(anchor="w")
        self.search = tk.StringVar()
        search = ttk.Entry(sidebar, textvariable=self.search)
        search.pack(fill="x", pady=8)
        self.search.trace_add("write", lambda *_: self.render_processes())
        self.process_tree = self.tree(sidebar, (("name", "Название", 185), ("pid", "PID", 65)), height=15)
        self.process_tree.bind("<<TreeviewSelect>>", self.process_selected)
        ttk.Button(sidebar, text="Обновить список", command=self.refresh_processes).pack(fill="x", pady=8)
        ttk.Label(sidebar, text="Выбор относится к PID.\nУ браузера сеть может идти\nчерез вспомогательный процесс.\n\nHTTPS виден как шифрованные\nданные; расшифровка не входит\nв эту версию.", wraplength=245).pack(anchor="w", pady=8)

        main = ttk.Panedwindow(panels, orient="vertical")
        panels.add(main, weight=4)
        connections = ttk.Frame(main)
        main.add(connections, weight=2)
        connection_header = ttk.Frame(connections)
        connection_header.pack(fill="x", pady=(0, 5))
        ttk.Label(connection_header, text="Соединения", style="Section.TLabel").pack(side="left")
        ttk.Button(connection_header, text="Все пакеты", command=self.show_all_packets).pack(side="right")
        self.connection_tree = self.tree(connections, (
            ("protocol", "Протокол", 75), ("source", "Откуда", 170), ("destination", "Куда", 170),
            ("process", "Процесс / PID", 130), ("count", "Пакеты", 65),
            ("sent", "Отправлено", 90), ("received", "Получено", 90)), height=6)
        self.connection_tree.bind("<<TreeviewSelect>>", self.connection_selected)

        packet_panel = ttk.Frame(main)
        main.add(packet_panel, weight=2)
        ttk.Label(packet_panel, text="Пакеты", style="Section.TLabel").pack(anchor="w", pady=5)
        self.packet_tree = self.tree(packet_panel, (
            ("time", "Время", 105), ("direction", "Направление", 95), ("protocol", "Протокол", 70),
            ("length", "Кадр", 70), ("summary", "Содержание", 440)), height=7)
        self.packet_tree.bind("<<TreeviewSelect>>", self.packet_selected)

        detail_panel = ttk.Frame(main)
        main.add(detail_panel, weight=3)
        self.notebook = ttk.Notebook(detail_panel)
        self.notebook.pack(fill="both", expand=True)
        self.details = self.text_tab("Детали пакета")
        self.hex_text = self.text_tab("HEX кадра")
        self.payload_text = self.text_tab("Данные пакета")
        self.stream_text = self.text_tab("Собранные данные")
        self.notebook.bind("<<NotebookTabChanged>>", self.tab_changed)
        self.set_text(self.details, "Выберите процесс и начните захват либо откройте сохранённый сеанс.")
        self.set_text(self.stream_text, "Выберите соединение. TCP собирается отдельно для каждого направления.\n"
                      "Пропуски обозначаются явно; UDP отображается отдельными датаграммами.")
        self.footer = tk.StringVar(value="0 пакетов · 0 Б · лимит 10 000 пакетов / 32 МиБ")
        ttk.Label(footer_panel, textvariable=self.footer).pack(anchor="w")
        ttk.Label(footer_panel, text="Счётчики соединений: наблюдаемые прикладные байты, включая повторы. «Откуда/Куда» — первый пакет.").pack(anchor="w")
        root.bind("<Control-o>", lambda _: self.open_session())
        root.bind("<Control-s>", lambda _: self.save_session())
        root.bind("<Command-o>", lambda _: self.open_session())
        root.bind("<Command-s>", lambda _: self.save_session())

    @staticmethod
    def tree(parent, columns, height):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=tuple(item[0] for item in columns), show="headings", selectmode="browse", height=height)
        for name, label, width in columns:
            tree.heading(name, text=label)
            tree.column(name, width=width, minwidth=45, stretch=True)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        return tree

    def text_tab(self, title):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=title)
        text = scrolledtext.ScrolledText(frame, wrap="word", font=("Menlo", 11), state="disabled")
        text.pack(fill="both", expand=True)
        return text

    @staticmethod
    def set_text(widget, value):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", value)
        widget.configure(state="disabled")

    def launch_lab(self):
        subprocess.Popen([sys.executable, str(ROOT / "network_lab.py"), "gui",
                          "--http-port", "0", "--tcp-port", "0", "--udp-port", "0"])
        self.status.set("Тестовый клиент запущен отдельно. Обновите список и выберите PID из его окна.")

    def refresh_processes(self):
        if self.process_refreshing:
            return
        self.process_refreshing = True
        def worker():
            try:
                self.background.put(("processes", list_processes()))
            except Exception as error:
                self.background.put(("process_error", str(error)))
        threading.Thread(target=worker, daemon=True).start()

    def render_processes(self):
        query = self.search.get().casefold()
        self.process_tree.delete(*self.process_tree.get_children())
        for item in self.processes:
            if query and query not in f"{item['name']} {item['pid']} {item.get('path', '')}".casefold():
                continue
            self.process_tree.insert("", "end", iid=str(item["pid"]), values=(item["name"], item["pid"]))
        if self.selected_pid and self.process_tree.exists(str(self.selected_pid)):
            self.process_tree.selection_set(str(self.selected_pid))

    def process_selected(self, _event=None):
        selected = self.process_tree.selection()
        if not selected:
            return
        pid = int(selected[0])
        if self.capture.running or self.stopping:
            if self.capture_pid and self.process_tree.exists(str(self.capture_pid)) and pid != self.capture_pid:
                self.process_tree.selection_set(str(self.capture_pid))
                self.status.set("Сначала остановите захват, чтобы выбрать другой процесс.")
            return
        self.selected_pid = pid
        item = next((p for p in self.processes if p["pid"] == pid), None)
        self.target.set(f"{item['name'] if item else 'Процесс'} · PID {pid}")

    def start_capture(self):
        if not self.selected_pid:
            self.status.set("Выберите процесс в списке слева.")
            return
        if self.capture.running or self.stopping or self.controls_busy:
            return
        if self.session.limit_reached:
            self.status.set("Лимит сеанса достигнут. Сохраните данные и очистите сеанс перед новым захватом.")
            return
        self.capture_pid = self.selected_pid
        self.capture_error = None
        self.run_queue_drops = 0
        self.run_kernel_drops = 0
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.open_button.configure(state="disabled")
        self.save_button.configure(state="disabled")
        self.clear_button.configure(state="disabled")
        self.status.set(f"Подключение к захвату для PID {self.capture_pid}…")
        try:
            self.capture.start({self.capture_pid})
        except Exception as error:
            self.status.set(f"Не удалось начать захват: {error}")
            self.capture_finished()

    def stop_capture(self):
        if self.stopping:
            return
        self.stopping = True
        self.stop_button.configure(state="disabled")
        self.status.set("Останавливаем захват…")
        self.capture.stop()
        # Completion is reported by the capture worker only after child cleanup.
        if not self.capture.running:
            self.capture_finished()

    def capture_finished(self):
        if self.capture.running:
            self.root.after(50, self.capture_finished)
            return
        requested_stop = self.stopping
        self.stopping = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.open_button.configure(state="normal")
        self.save_button.configure(state="normal")
        self.clear_button.configure(state="normal")
        if requested_stop:
            self.status.set(self.capture_error or ("Лимит сеанса достигнут; захват остановлен." if self.session.limit_reached
                            else "Захват остановлен. Можно изучить или сохранить сеанс."))

    def clear(self):
        if self.capture.running or self.stopping or self.controls_busy:
            return
        if self.dirty and not messagebox.askyesno("Очистить сеанс", "Удалить из окна несохранённые пакеты этого сеанса?", parent=self.root):
            return
        self.session = Session()
        self.dirty = False
        self.dropped = 0
        self.kernel_dropped = None
        self.loss_note = None
        self.selected_connection = None
        self.packet_filter = None
        self.reset_tables()
        self.status.set("Пустой сеанс. Можно начать захват.")

    def reset_tables(self):
        self.rendered_packets = 0
        for tree in (self.connection_tree, self.packet_tree):
            tree.delete(*tree.get_children())
        for widget in (self.details, self.hex_text, self.payload_text, self.stream_text):
            self.set_text(widget, "Выберите пакет или соединение.")
        self.render_connections()
        self.render_packets()
        self.update_footer()
        connections = self.connection_tree.get_children()
        if connections:
            self.connection_tree.selection_set(connections[0])
            self.notebook.select(3)

    @staticmethod
    def endpoint(address, port):
        if not address:
            return "Неизвестно"
        address = f"[{address}]" if ":" in address else address
        return f"{address}:{port}" if port is not None else address

    def render_connections(self):
        for conn in self.session.connections():
            iid = str(conn["id"])
            values = (conn["protocol"], self.endpoint(conn["src"], conn["sport"]),
                      self.endpoint(conn["dst"], conn["dport"]),
                      f"{conn.get('process') or '?'} / {conn.get('pid') or '?'}", conn["packet_count"],
                      format_size(conn["sent_bytes"]), format_size(conn["received_bytes"]))
            if self.connection_tree.exists(iid):
                self.connection_tree.item(iid, values=values)
            else:
                self.connection_tree.insert("", "end", iid=iid, values=values)

    def connection_selected(self, _event=None):
        selection = self.connection_tree.selection()
        if selection:
            self.selected_connection = int(selection[0])
            self.packet_filter = self.selected_connection
            self.render_packets(rebuild=True)
            self.render_stream()
            packets = self.session.connection_packets(self.selected_connection)
            if packets:
                first = next((packet for packet in packets if packet["payload"]), packets[0])
                self.packet_tree.selection_set(str(first["id"]))

    def show_all_packets(self):
        self.packet_filter = None
        self.connection_tree.selection_remove(*self.connection_tree.selection())
        self.selected_connection = None
        self.render_packets(rebuild=True)
        self.set_text(self.stream_text, "Выберите соединение для просмотра собранных данных.")

    def render_packets(self, rebuild=False):
        if rebuild:
            self.packet_tree.delete(*self.packet_tree.get_children())
            self.rendered_packets = 0
        packets = self.session.packets[self.rendered_packets:]
        for packet in packets:
            if self.packet_filter is not None and packet["connection_id"] != self.packet_filter:
                continue
            iid = str(packet["id"])
            if self.packet_tree.exists(iid):
                continue
            try:
                timestamp = datetime.fromtimestamp(packet["timestamp"]).strftime("%H:%M:%S.%f")[:-3]
            except (ValueError, OSError, OverflowError):
                timestamp = "?"
            direction = {"in": "← Входящий", "out": "→ Исходящий"}.get(packet["direction"], "Неизвестно")
            self.packet_tree.insert("", "end", iid=iid, values=(timestamp, direction, packet["protocol"],
                                    format_size(packet["wire_length"]), packet["summary"]))
        self.rendered_packets = len(self.session.packets)

    def packet_selected(self, _event=None):
        selection = self.packet_tree.selection()
        if not selection:
            return
        packet = self.session.packet(int(selection[0]))
        fields = {
            "Пакет": packet["id"], "Процесс": packet["process"] or "Неизвестен",
            "PID": packet["pid"], "Effective PID": packet.get("effective_pid"),
            "Effective process": packet.get("effective_process"),
            "Интерфейс": packet["interface"] or "Неизвестен", "Направление": packet["direction"],
            "Протокол": packet["protocol"], "Откуда": self.endpoint(packet["src"], packet["sport"]),
            "Куда": self.endpoint(packet["dst"], packet["dport"]),
            "Длина кадра": packet["wire_length"], "Захвачено байт": len(packet["raw"]),
            "Прикладные байты": len(packet["payload"]), "TCP sequence": packet.get("tcp_seq"),
            "TCP flags": packet.get("tcp_flags"), "Link type": packet["linktype"],
        }
        description = "\n".join(f"{label}: {value}" for label, value in fields.items() if value is not None)
        if packet["issues"]:
            description += "\n\nОграничения:\n" + "\n".join(packet["issues"])
        self.set_text(self.details, description)
        self.set_text(self.hex_text, hex_dump(packet["raw"]))
        self.set_text(self.payload_text, readable(packet["payload"]))

    def tab_changed(self, _event=None):
        if self.notebook.index("current") == 3:
            self.render_stream()

    def render_stream(self):
        if self.selected_connection is None:
            return
        parts = self.session.stream(self.selected_connection)
        output = list(self.session.notes)
        shown = 0
        for part in parts:
            if shown >= PREVIEW_LIMIT:
                output.append("Просмотр ограничен 256 КиБ. Все сохранённые байты остаются в сеансе.")
                break
            output.append(f"━━ {part['name']} · {format_size(len(part['data']))} ━━")
            if part["issues"]:
                output.append("Ограничения: " + "; ".join(part["issues"]))
            remaining = PREVIEW_LIMIT - shown
            output.append(readable(part["data"][:remaining]))
            if len(part["data"]) > remaining:
                output.append(f"Эта часть усечена в просмотре: показано {format_size(remaining)} из "
                              f"{format_size(len(part['data']))}. Полные сохранённые байты остаются в сеансе.")
            shown += min(len(part["data"]), remaining)
        self.set_text(self.stream_text, "\n\n".join(output) or "Пока нет прикладных данных.")
        self.last_stream_render = time.monotonic()

    def set_file_busy(self, busy):
        self.controls_busy = busy
        for button in (self.start_button, self.open_button, self.save_button, self.clear_button):
            button.configure(state="disabled" if busy else "normal")

    def open_session(self, path=None):
        if self.capture.running or self.stopping or self.controls_busy:
            return
        if self.dirty and not messagebox.askyesno("Открыть другой сеанс", "Заменить несохранённый сеанс в окне?", parent=self.root):
            return
        if path is None:
            path = filedialog.askopenfilename(parent=self.root, title="Открыть сеанс",
                       filetypes=(("Net View / pcapng", "*.json *.pcapng"), ("Все файлы", "*")))
        if not path:
            return
        path = Path(path)
        self.set_file_busy(True)
        self.status.set(f"Открываем {path.name}…")
        def worker():
            try:
                if path.suffix.lower() == ".pcapng":
                    session = Session()
                    with path.open("rb") as stream:
                        for frame in parse_pcapng(stream):
                            if session.add(frame) is None:
                                break
                else:
                    session = Session.load(path)
                self.background.put(("loaded", (session, path)))
            except Exception as error:
                self.background.put(("file_error", str(error)))
        threading.Thread(target=worker, daemon=True).start()

    def save_session(self):
        if self.capture.running or self.stopping:
            self.status.set("Остановите захват перед сохранением сеанса.")
            return
        if self.controls_busy:
            return
        path = filedialog.asksaveasfilename(parent=self.root, title="Сохранить сеанс",
                       defaultextension=".netview.json", initialfile="capture.netview.json",
                       filetypes=(("Сеанс Net View", "*.netview.json"),))
        if not path:
            return
        self.set_file_busy(True)
        self.status.set("Сохраняем исходные пакеты и метаданные…")
        def worker():
            try:
                self.session.save(path)
                self.background.put(("saved", path))
            except Exception as error:
                self.background.put(("file_error", str(error)))
        threading.Thread(target=worker, daemon=True).start()

    def update_footer(self):
        limit = " · ДОСТИГНУТ ЛИМИТ" if self.session.limit_reached else ""
        kernel = "неизвестно" if self.kernel_dropped is None else str(self.kernel_dropped)
        self.footer.set(f"{len(self.session.packets)} пакетов · {format_size(self.session.total_bytes)} · "
                        f"потери очереди: {self.dropped} · потери ядра: {kernel} · "
                        f"лимит {self.session.max_packets} / {format_size(self.session.max_bytes)}{limit}")

    def record_losses(self):
        prefix = "Захват неполный: потери очереди "
        if self.loss_note in self.session.notes:
            self.session.notes.remove(self.loss_note)
        if self.dropped or self.kernel_dropped:
            note = f"{prefix}{self.dropped}; потери ядра {self.kernel_dropped if self.kernel_dropped is not None else 'неизвестны'}."
            if len(self.session.notes) < 64:
                self.session.notes.append(note)
                self.loss_note = note
            self.dirty = True

    def poll(self):
        if self.closed:
            return
        changed = False
        for _ in range(250):
            try:
                event = self.capture.events.get_nowait()
            except queue.Empty:
                break
            kind = event["type"]
            if kind == "packet":
                try:
                    packet = self.session.add(event["frame"])
                except (ValueError, TypeError) as error:
                    self.stop_capture()
                    self.capture_error = f"Некорректные данные захвата: {error}"
                    self.status.set(self.capture_error)
                    continue
                if packet is not None:
                    self.dirty = True
                    changed = True
                if self.session.limit_reached and not self.stopping:
                    self.stop_capture()
                    self.status.set("Достигнут лимит сеанса. Захват остановлен; сохраните данные.")
            elif kind == "ready":
                self.status.set(f"Захват активен · PID {self.capture_pid} · данные только с момента начала наблюдения")
            elif kind == "error":
                self.capture_error = "Ошибка захвата: " + event["message"]
                self.status.set(self.capture_error)
            elif kind == "stopped":
                self.capture_finished()
            elif kind == "stats":
                drops = event.get("dropped", self.run_queue_drops)
                self.dropped += max(0, drops - self.run_queue_drops)
                self.run_queue_drops = drops
                kernel = event.get("kernel_dropped")
                if kernel is not None:
                    self.kernel_dropped = (self.kernel_dropped or 0) + max(0, kernel - self.run_kernel_drops)
                    self.run_kernel_drops = kernel
                self.record_losses()
                self.update_footer()
        try:
            while True:
                kind, value = self.background.get_nowait()
                if kind == "processes":
                    self.process_refreshing = False
                    self.processes = value
                    self.render_processes()
                elif kind == "process_error":
                    self.process_refreshing = False
                    self.status.set("Не удалось обновить процессы: " + value)
                elif kind == "loaded":
                    self.session, path = value
                    self.dirty = False
                    self.dropped = 0
                    self.kernel_dropped = None
                    self.loss_note = None
                    self.selected_connection = None
                    self.packet_filter = None
                    self.set_file_busy(False)
                    self.reset_tables()
                    self.status.set(f"Открыт {path.name} · {len(self.session.packets)} пакетов" +
                                    (" · показано до лимита памяти" if self.session.limit_reached else ""))
                elif kind == "saved":
                    self.dirty = False
                    self.set_file_busy(False)
                    self.status.set(f"Сеанс сохранён: {value}")
                elif kind == "file_error":
                    self.set_file_busy(False)
                    self.status.set("Ошибка файла: " + value)
        except queue.Empty:
            pass
        if changed:
            self.render_connections()
            self.render_packets()
            self.update_footer()
            if self.notebook.index("current") == 3 and time.monotonic() - self.last_stream_render > 0.5:
                self.render_stream()
        self.root.after(100, self.poll)

    def close(self):
        if self.controls_busy:
            self.status.set("Дождитесь завершения работы с файлом перед закрытием.")
            return
        if self.dirty and not messagebox.askyesno("Закрыть Net View", "Закрыть окно без сохранения текущего сеанса?", parent=self.root):
            return
        self.closed = True
        self.capture.stop()
        self.status.set("Завершаем процесс захвата…")
        def finish():
            if self.capture.running:
                self.root.after(100, finish)
            else:
                self.root.destroy()
        finish()


def run(initial_file=None):
    root = tk.Tk()
    Inspector(root, initial_file)
    root.mainloop()
