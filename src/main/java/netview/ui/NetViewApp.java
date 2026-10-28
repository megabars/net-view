package netview.ui;

import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.geometry.Insets;
import javafx.geometry.Orientation;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Duration;
import netview.capture.*;
import netview.model.*;
import netview.session.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.function.Function;

/** JavaFX owns the visible state; file I/O and capture/reassembly run on workers. */
public final class NetViewApp extends Application {
    private final ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
    private final ExecutorService previews = Executors.newSingleThreadExecutor(Thread.ofVirtual().factory());
    private volatile long packetRevision;
    private final CaptureAdapter capture = new MacCaptureAdapter();
    private final ObservableList<ProcessInfo> processes = FXCollections.observableArrayList();
    private final ObservableList<Connection> connections = FXCollections.observableArrayList();
    private final ObservableList<SessionPacket> packets = FXCollections.observableArrayList();
    private Session session = new Session();
    private Stage stage;
    private TableView<ProcessInfo> processTable;
    private TableView<Connection> connectionTable;
    private TableView<SessionPacket> packetTable;
    private final Label status = new Label("Выберите процесс или откройте сохранённый сеанс.");
    private final Label target = new Label("Процесс не выбран");
    private final Label totals = new Label();
    private final Button start = new Button("Начать захват");
    private final Button stop = new Button("Остановить");
    private final Button open = new Button("Открыть сеанс…");
    private final Button save = new Button("Сохранить…");
    private final Button clear = new Button("Новый сеанс");
    private final TextArea details = area(), hex = area(), payload = area(), streams = area();
    private final TabPane tabs = new TabPane();
    private Timeline timer;
    private Long selectedPid, capturePid, selectedConnection;
    private long drops, runDrops, runKernelDrops;
    private Long kernelDrops;
    private boolean busy, dirty, stopping, closing, changingSelection;
    private boolean captureActive, terminalEventSeen;
    private boolean streamBusy;
    private long streamRevision;
    private long lastStreamRefresh;
    private int renderedPacketCount;
    private String error, lossNote;
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    @Override public void start(Stage window) {
        stage = window;
        BorderPane root = new BorderPane(); root.setPadding(new Insets(18));
        Label title = new Label("Net View"); title.getStyleClass().add("title");
        Label subtitle = new Label("Сетевая активность приложений"); subtitle.getStyleClass().add("muted");
        Region spacer = new Region(); HBox.setHgrow(spacer, Priority.ALWAYS);
        Button lab = new Button("Тестовый клиент"); lab.setOnAction(e -> launchLab());
        HBox header = new HBox(14, title, subtitle, spacer, lab); header.getStyleClass().add("header");
        start.getStyleClass().add("primary");
        start.setOnAction(e -> startCapture()); stop.setOnAction(e -> stopCapture());
        open.setOnAction(e -> chooseOpen()); save.setOnAction(e -> chooseSave()); clear.setOnAction(e -> newSession());
        HBox toolbar = new HBox(8, start, stop, open, save, clear);
        status.setWrapText(true); status.getStyleClass().add("status");
        VBox top = new VBox(12, header, toolbar, status); top.setPadding(new Insets(0, 0, 14, 0)); root.setTop(top);

        TextField search = new TextField(); search.setPromptText("Название или PID");
        search.setAccessibleText("Поиск процесса");
        FilteredList<ProcessInfo> filtered = new FilteredList<>(processes);
        search.textProperty().addListener((obs, before, query) -> {
            String term = query.toLowerCase(Locale.ROOT);
            filtered.setPredicate(p -> (p.name() + " " + p.pid() + " " + p.path()).toLowerCase(Locale.ROOT).contains(term));
        });
        processTable = new TableView<>(filtered); processTable.setPlaceholder(new Label("Нет подходящих процессов"));
        column(processTable, "Процесс", p -> p.name(), 180); column(processTable, "PID", p -> Long.toString(p.pid()), 75);
        processTable.getSelectionModel().selectedItemProperty().addListener((obs, old, item) -> {
            if (item != null && !changingSelection) {
                if (captureActive || stopping) { status.setText("Остановите захват перед выбором другого процесса."); return; }
                selectedPid = item.pid(); target.setText(item.name() + " · PID " + selectedPid); updateControls();
            }
        });
        Button refresh = new Button("Обновить процессы"); refresh.setMaxWidth(Double.MAX_VALUE); refresh.setOnAction(e -> refreshProcesses());
        Label note = new Label("Выбирается один процесс. Браузер может использовать отдельный сетевой процесс.\n\nHTTPS доступен как зашифрованные байты.");
        note.setWrapText(true); note.getStyleClass().add("muted"); target.setWrapText(true);
        VBox sidebar = new VBox(10, section("Приложения и процессы"), search, processTable, refresh, target, note);
        sidebar.setMinWidth(225); sidebar.setPrefWidth(270); VBox.setVgrow(processTable, Priority.ALWAYS);

        connectionTable = new TableView<>(connections); connectionTable.setPlaceholder(new Label("Соединения появятся после начала захвата"));
        column(connectionTable, "Протокол", Connection::protocol, 85);
        column(connectionTable, "Откуда", c -> DisplayFormat.endpoint(c.src(), c.sourcePort()), 190);
        column(connectionTable, "Куда", c -> DisplayFormat.endpoint(c.dst(), c.destinationPort()), 190);
        column(connectionTable, "Процесс / PID", c -> (c.process().isBlank() ? "?" : c.process()) + " / " + Objects.toString(c.pid(), "?"), 145);
        column(connectionTable, "Пакеты", c -> Long.toString(c.packetCount()), 75);
        column(connectionTable, "Отправлено", c -> DisplayFormat.size(c.sentBytes()), 100);
        column(connectionTable, "Получено", c -> DisplayFormat.size(c.receivedBytes()), 100);
        connectionTable.getSelectionModel().selectedItemProperty().addListener((obs, old, item) -> {
            if (!changingSelection && item != null) {
                selectedConnection = item.id(); renderPackets(true); renderStream(); selectPayload();
            }
        });
        Button all = new Button("Все пакеты"); all.setOnAction(e -> {
            selectedConnection = null; connectionTable.getSelectionModel().clearSelection(); renderPackets(true);
            streams.setText("Выберите соединение для сборки данных."); streamRevision++;
        });
        HBox connectionHeader = new HBox(12, section("Соединения"), all);
        VBox connectionPane = new VBox(8, connectionHeader, connectionTable); VBox.setVgrow(connectionTable, Priority.ALWAYS);
        packetTable = new TableView<>(packets); packetTable.setPlaceholder(new Label("Здесь будут отдельные пакеты"));
        column(packetTable, "Время", p -> timestamp(p.decoded().frame().timestamp()), 115);
        column(packetTable, "Направление", p -> direction(p.decoded().frame().direction()), 120);
        column(packetTable, "Протокол", p -> p.decoded().protocol(), 80);
        column(packetTable, "Кадр", p -> DisplayFormat.size(p.decoded().wireLength()), 85);
        column(packetTable, "Содержание", p -> p.decoded().summary(), 520);
        packetTable.getSelectionModel().selectedItemProperty().addListener((obs, old, item) -> { if (item != null) showPacket(item); });
        VBox packetPane = new VBox(8, section("Пакеты"), packetTable); VBox.setVgrow(packetTable, Priority.ALWAYS);
        tabs.getTabs().addAll(tab("Детали", details), tab("HEX кадра", hex), tab("Данные пакета", payload), tab("Собранные данные", streams));
        tabs.getSelectionModel().selectedIndexProperty().addListener((obs, old, value) -> { if (value.intValue() == 3) renderStream(); });
        SplitPane main = new SplitPane(connectionPane, packetPane, tabs); main.setOrientation(Orientation.VERTICAL); main.setDividerPositions(.30, .59);
        SplitPane content = new SplitPane(sidebar, main); content.setDividerPositions(.23); root.setCenter(content);
        Label countersNote = new Label("Счётчики: наблюдаемые прикладные байты, включая повторы. Адреса соединения — по первому пакету.");
        countersNote.getStyleClass().add("muted"); countersNote.setWrapText(true);
        VBox footer = new VBox(4, totals, countersNote); footer.setPadding(new Insets(12, 0, 0, 0)); root.setBottom(footer);
        Scene scene = new Scene(root, 1320, 860);
        scene.getStylesheets().add(Objects.requireNonNull(getClass().getResource("/netview/style.css")).toExternalForm());
        stage.setTitle("Net View — сетевой инспектор"); stage.setScene(scene); stage.setMinWidth(1000); stage.setMinHeight(680);
        stage.setOnCloseRequest(e -> { e.consume(); closeWindow(); }); stage.show();
        timer = new Timeline(new KeyFrame(Duration.millis(150), e -> poll())); timer.setCycleCount(Timeline.INDEFINITE); timer.play();
        updateControls(); updateTotals(); refreshProcesses();
        List<String> args = getParameters().getRaw();
        if (args.size() == 2 && args.getFirst().equals("--open")) openFile(Path.of(args.get(1)));
    }
    private static Label section(String text) { Label label = new Label(text); label.getStyleClass().add("section"); return label; }
    private static TextArea area() { TextArea text = new TextArea(); text.setEditable(false); text.setWrapText(true); text.getStyleClass().add("data"); return text; }
    private static Tab tab(String label, TextArea content) { Tab tab = new Tab(label, content); tab.setClosable(false); return tab; }
    private static <T> void column(TableView<T> table, String label, Function<T, String> value, double width) {
        TableColumn<T, String> column = new TableColumn<>(label); column.setPrefWidth(width);
        column.setCellValueFactory(item -> new ReadOnlyStringWrapper(value.apply(item.getValue()))); table.getColumns().add(column);
    }
    private static String timestamp(double value) {
        try { long seconds = (long) Math.floor(value); return TIME.format(Instant.ofEpochSecond(seconds, (long) ((value - seconds) * 1e9))); }
        catch (RuntimeException e) { return "Неизвестно"; }
    }
    private static String direction(String value) { return switch (value) { case "in" -> "← Входящий"; case "out" -> "→ Исходящий"; default -> "Неизвестно"; }; }
    private void refreshProcesses() {
        workers.submit(() -> {
            try { List<ProcessInfo> items = ProcessCatalog.list(); onUi(() -> {
                changingSelection = true; processes.setAll(items);
                if (selectedPid != null) items.stream().filter(p -> p.pid() == selectedPid).findFirst().ifPresent(p -> processTable.getSelectionModel().select(p));
                changingSelection = false;
            }); } catch (Exception e) { onUi(() -> fail("Не удалось получить процессы", e)); }
        });
    }
    private void startCapture() {
        if (selectedPid == null || busy || captureActive || capture.running() || stopping) return;
        if (session.limitReached()) { status.setText("Лимит сеанса достигнут. Сохраните его и создайте новый."); return; }
        capturePid = selectedPid; error = null; runDrops = runKernelDrops = 0; terminalEventSeen = false;
        captureActive = true;
        try { capture.start(Set.of(capturePid)); status.setText("Запуск захвата PID " + capturePid + "…"); }
        catch (RuntimeException e) { captureActive = false; fail("Не удалось начать захват", e); }
        updateControls();
    }
    private void stopCapture() { if (captureActive && !stopping) { stopping = true; capture.stop(); status.setText("Останавливаем захват…"); updateControls(); } }
    private void poll() {
        if (closing) return;
        boolean changed = false;
        long deadline = System.nanoTime() + 12_000_000L;
        CaptureEvent event;
        for (int i = 0; i < 128 && System.nanoTime() < deadline && (event = capture.poll()) != null; i++) {
            switch (event.type()) {
                case "packet" -> {
                    try { synchronized (session) { changed |= session.add(event.frame()) != null; dirty |= changed; } }
                    catch (RuntimeException e) { error = "Некорректные данные захвата: " + e.getMessage(); stopCapture(); status.setText(error); }
                    if (session.limitReached()) { stopCapture(); status.setText("Достигнут лимит сеанса. Захват останавливается."); }
                }
                case "ready" -> status.setText("Захват активен · PID " + capturePid + " · только данные с начала наблюдения");
                case "error" -> { error = event.message(); status.setText("Ошибка захвата: " + error.lines().findFirst().orElse(error)); details.setText(error); tabs.getSelectionModel().select(0); }
                case "stats" -> {
                    drops += Math.max(0, event.dropped() - runDrops); runDrops = event.dropped();
                    if (event.kernelDropped() != null) { kernelDrops = (kernelDrops == null ? 0 : kernelDrops) + Math.max(0, event.kernelDropped() - runKernelDrops); runKernelDrops = event.kernelDropped(); }
                    recordLosses(); updateTotals();
                }
                case "stopped" -> { terminalEventSeen = true; if (error == null) status.setText(session.limitReached() ? "Лимит достигнут; захват остановлен." : "Захват остановлен. Можно сохранить сеанс."); }
                default -> { }
            }
        }
        if (terminalEventSeen && !capture.running()) { stopping = false; captureActive = false; }
        updateControls();
        if (changed) {
            renderConnections(); renderPackets(false); updateTotals();
            if (tabs.getSelectionModel().getSelectedIndex() == 3 && System.nanoTime() - lastStreamRefresh > 700_000_000L) renderStream();
        }
    }
    private void recordLosses() {
        if (drops == 0 && (kernelDrops == null || kernelDrops == 0)) return;
        synchronized (session) {
            if (lossNote != null) session.notes().remove(lossNote);
            lossNote = "Захват неполный: потери очереди " + drops + "; потери ядра " + Objects.toString(kernelDrops, "неизвестны") + ".";
            if (session.notes().size() < 64) session.notes().add(lossNote);
        }
        dirty = true;
    }
    private void updateControls() {
        boolean active = captureActive || capture.running() || stopping;
        start.setDisable(busy || active || selectedPid == null); stop.setDisable(!active || stopping);
        open.setDisable(busy || active); save.setDisable(busy || active || session.packetCount() == 0); clear.setDisable(busy || active);
        processTable.setDisable(active); // The highlighted PID must remain the capture target.
    }
    private void updateTotals() {
        totals.setText(session.packetCount() + " пакетов · " + DisplayFormat.size(session.totalBytes())
                + " · потери очереди: " + drops + " · ядра: " + Objects.toString(kernelDrops, "неизвестно")
                + " · лимит " + session.maxPackets() + " / " + DisplayFormat.size(session.maxBytes())
                + (session.limitReached() ? " · ЛИМИТ ДОСТИГНУТ" : ""));
    }
    private void renderConnections() {
        changingSelection = true; connections.setAll(session.connections());
        if (selectedConnection != null) connections.stream().filter(c -> c.id() == selectedConnection).findFirst().ifPresent(c -> connectionTable.getSelectionModel().select(c));
        changingSelection = false;
    }
    private void renderPackets(boolean reset) {
        if (reset) { packets.clear(); renderedPacketCount = 0; }
        List<SessionPacket> all = session.packets();
        for (int i = renderedPacketCount; i < all.size(); i++) {
            SessionPacket item = all.get(i); if (selectedConnection == null || item.connectionId() == selectedConnection) packets.add(item);
        }
        renderedPacketCount = all.size();
    }
    private void selectPayload() {
        packets.stream().filter(p -> p.decoded().payloadLength() > 0).findFirst().or(() -> packets.stream().findFirst())
                .ifPresent(p -> packetTable.getSelectionModel().select(p));
    }
    private void showPacket(SessionPacket packet) {
        DecodedPacket p = packet.decoded(); CapturedFrame f = p.frame();
        details.setText("Пакет: " + packet.id() + "\nПроцесс: " + f.process() + "\nPID: " + f.pid()
                + "\nEffective PID: " + f.effectivePid() + "\nEffective process: " + f.effectiveProcess()
                + "\nИнтерфейс: " + f.networkInterface() + "\nНаправление: " + direction(f.direction())
                + "\nПротокол: " + p.protocol() + "\nОткуда: " + DisplayFormat.endpoint(p.src(), p.sourcePort())
                + "\nКуда: " + DisplayFormat.endpoint(p.dst(), p.destinationPort()) + "\nДлина кадра: " + p.wireLength()
                + "\nЗахвачено: " + f.capturedLength() + "\nПрикладные байты: " + p.payloadLength()
                + "\nTCP sequence: " + p.tcpSequence() + "\nTCP flags: " + p.tcpFlags() + "\nLink type: " + f.linktype()
                + (p.issues().isEmpty() ? "" : "\n\nОграничения:\n" + String.join("\n", p.issues())));
        payload.setText("Подготовка данных…"); hex.setText("Подготовка HEX…");
        long id = packet.id(), revision = ++packetRevision; Session reference = session;
        previews.submit(() -> { if (revision != packetRevision) return;
            String text = DisplayFormat.hex(f.data()), readable = DisplayFormat.readable(p.payload()); onUi(() -> {
            SessionPacket selected = packetTable.getSelectionModel().getSelectedItem();
            if (session == reference && revision == packetRevision && selected != null && selected.id() == id) { hex.setText(text); payload.setText(readable); }
        }); });
    }
    private void renderStream() {
        if (selectedConnection == null || streamBusy) return;
        Session reference = session; long id = selectedConnection, revision = ++streamRevision;
        streamBusy = true; lastStreamRefresh = System.nanoTime();
        workers.submit(() -> {
            try {
                List<SessionPacket> snapshot; List<String> notes;
                synchronized (reference) { snapshot = reference.connectionPackets(id); notes = List.copyOf(reference.notes()); }
                List<StreamPart> parts = Session.reconstruct(snapshot);
                StringBuilder text = new StringBuilder(String.join("\n", notes)); int shown = 0;
                for (StreamPart part : parts) {
                    if (shown >= DisplayFormat.PREVIEW_LIMIT || text.length() >= DisplayFormat.PREVIEW_LIMIT) { text.append("\n\nПредпросмотр ограничен; остальные части и исходные байты сохранены в сеансе."); break; }
                    text.append("\n\n━━ ").append(part.name()).append(" · ").append(DisplayFormat.size(part.length())).append(" ━━\n");
                    if (!part.issues().isEmpty()) text.append("Ограничения: ").append(String.join("; ", part.issues())).append("\n");
                    byte[] data = part.data(); int remaining = DisplayFormat.PREVIEW_LIMIT - shown;
                    text.append(DisplayFormat.readable(data, remaining));
                    if (data.length > remaining) text.append("\nЭта часть усечена только в просмотре; исходные байты сохранены.");
                    shown += Math.min(data.length, remaining);
                    if (text.length() > DisplayFormat.PREVIEW_LIMIT) {
                        text.setLength(DisplayFormat.PREVIEW_LIMIT);
                        text.append("\n\nПредпросмотр ограничен; остальные части и исходные байты сохранены в сеансе."); break;
                    }
                }
                String result = text.toString().strip();
                onUi(() -> { streamBusy = false;
                    if (reference == session && Objects.equals(selectedConnection, id) && revision == streamRevision) streams.setText(result.isEmpty() ? "Пока нет прикладных данных." : result);
                    else if (selectedConnection != null) renderStream();
                });
            } catch (Exception e) { onUi(() -> { streamBusy = false; fail("Не удалось собрать поток", e); }); }
        });
    }
    private boolean discardConfirmed() {
        if (!dirty) return true;
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION, "Продолжить без сохранения текущего сеанса?", ButtonType.YES, ButtonType.CANCEL);
        alert.initOwner(stage); alert.setHeaderText("Есть несохранённые пакеты");
        return alert.showAndWait().orElse(ButtonType.CANCEL) == ButtonType.YES;
    }
    private void newSession() { if (discardConfirmed()) replaceSession(new Session(), "Новый сеанс. Выберите процесс и начните захват."); }
    private void replaceSession(Session replacement, String message) {
        session = replacement; selectedConnection = null; renderedPacketCount = 0; packetRevision++; packets.clear();
        drops = runDrops = runKernelDrops = 0; kernelDrops = null; lossNote = null; dirty = false; error = null; streamRevision++;
        details.clear(); hex.clear(); payload.clear(); streams.clear(); renderConnections(); renderPackets(true); updateTotals(); updateControls(); status.setText(message);
        if (!connections.isEmpty()) { connectionTable.getSelectionModel().selectFirst(); tabs.getSelectionModel().select(3); }
    }
    private FileChooser chooser(String title) {
        FileChooser chooser = new FileChooser(); chooser.setTitle(title);
        chooser.getExtensionFilters().addAll(new FileChooser.ExtensionFilter("Сеанс Net View", "*.netview.json", "*.json"),
                new FileChooser.ExtensionFilter("PCAPNG", "*.pcapng")); return chooser;
    }
    private void chooseOpen() {
        if (!discardConfirmed()) return;
        var file = chooser("Открыть сеанс").showOpenDialog(stage); if (file != null) openFile(file.toPath());
    }
    private void openFile(Path path) {
        busy = true; updateControls(); status.setText("Открываем " + path.getFileName() + "…");
        workers.submit(() -> {
            try {
                Session loaded;
                if (path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".pcapng")) {
                    loaded = new Session();
                    try (PcapngReader reader = new PcapngReader(Files.newInputStream(path))) {
                        CapturedFrame frame; while ((frame = reader.next()) != null && loaded.add(frame) != null) { }
                    }
                } else loaded = SessionStore.load(path);
                Session result = loaded; onUi(() -> { busy = false; replaceSession(result, "Открыт " + path.getFileName()); });
            } catch (Exception e) { onUi(() -> { busy = false; updateControls(); fail("Не удалось открыть сеанс", e); }); }
        });
    }
    private void chooseSave() {
        FileChooser chooser = chooser("Сохранить сеанс"); chooser.setInitialFileName("capture.netview.json");
        chooser.getExtensionFilters().setAll(new FileChooser.ExtensionFilter("Сеанс Net View", "*.netview.json", "*.json"));
        var file = chooser.showSaveDialog(stage); if (file == null) return;
        busy = true; updateControls(); Session reference = session;
        workers.submit(() -> {
            try { synchronized (reference) { SessionStore.save(reference, file.toPath()); }
                onUi(() -> { busy = false; dirty = false; updateControls(); status.setText("Сохранено: " + file); });
            } catch (Exception e) { onUi(() -> { busy = false; updateControls(); fail("Не удалось сохранить сеанс", e); }); }
        });
    }
    private void launchLab() {
        Path root = Path.of(System.getProperty("netview.projectDir", ".")).toAbsolutePath();
        Path lab = root.resolve("network_lab.py");
        if (!Files.isRegularFile(lab)) { status.setText("Тестовая лаборатория не найдена рядом с проектом: " + lab); return; }
        workers.submit(() -> {
            try { new ProcessBuilder("python3", lab.toString(), "gui", "--http-port", "0", "--tcp-port", "0", "--udp-port", "0").inheritIO().start();
                onUi(() -> status.setText("Лаборатория запущена отдельно. Обновите процессы и выберите PID из её окна."));
            } catch (Exception e) { onUi(() -> fail("Для лаборатории нужен Python 3 с Tk", e)); }
        });
    }
    private void fail(String action, Exception e) {
        String message = action + ": " + Objects.toString(e.getMessage(), e.getClass().getSimpleName());
        status.setText(message); details.setText(message); tabs.getSelectionModel().select(0);
    }
    private void onUi(Runnable action) { Platform.runLater(() -> { if (!closing) action.run(); }); }
    private void closeWindow() {
        if (busy) { status.setText("Дождитесь завершения работы с файлом."); return; }
        if (closing || !discardConfirmed()) return;
        closing = true; timer.stop(); status.setText("Завершаем захват…");
        workers.submit(() -> { capture.close(); Platform.runLater(() -> { stage.hide(); Platform.exit(); }); });
    }
    @Override public void stop() { packetRevision++; capture.close(); previews.close(); workers.close(); }
}
