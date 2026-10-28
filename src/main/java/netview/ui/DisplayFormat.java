package netview.ui;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;

public final class DisplayFormat {
    public static final int PREVIEW_LIMIT = 256 * 1024;
    private static final ObjectMapper JSON = new ObjectMapper().enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private DisplayFormat() {}
    public static String size(long bytes) {
        if (bytes >= 1024 * 1024) return String.format(Locale.ROOT, "%.1f МиБ", bytes / 1048576.0);
        if (bytes >= 1024) return String.format(Locale.ROOT, "%.1f КиБ", bytes / 1024.0);
        return bytes + " Б";
    }
    public static String endpoint(String address, Integer port) {
        if (address == null || address.isBlank()) return "Неизвестно";
        String host = address.contains(":") ? "[" + address + "]" : address;
        return port == null ? host : host + ":" + port;
    }
    public static String hex(byte[] data) {
        int limit = Math.min(data.length, PREVIEW_LIMIT);
        StringBuilder out = new StringBuilder();
        for (int offset = 0; offset < limit; offset += 16) {
            out.append(String.format("%06x  ", offset));
            StringBuilder ascii = new StringBuilder();
            for (int i = 0; i < 16; i++) {
                if (offset + i < limit) {
                    int value = Byte.toUnsignedInt(data[offset + i]);
                    out.append(String.format("%02x ", value));
                    ascii.append(value >= 32 && value < 127 ? (char) value : '.');
                } else out.append("   ");
            }
            out.append(" ").append(ascii).append('\n');
        }
        if (data.length > limit) out.append("\nПредпросмотр ограничен; исходные байты сохранены в сеансе.");
        return out.isEmpty() ? "Нет данных." : out.toString();
    }
    public static String readable(byte[] original) {
        return readable(original, PREVIEW_LIMIT);
    }
    public static String readable(byte[] original, int previewLimit) {
        if (previewLimit < 1 || previewLimit > PREVIEW_LIMIT) throw new IllegalArgumentException("Invalid preview limit");
        if (original.length == 0) return "Нет прикладных данных (например, подтверждение TCP).";
        if (original.length >= 3 && original[0] >= 20 && original[0] <= 23 && original[1] == 3
                && Byte.toUnsignedInt(original[2]) <= 4)
            return "Заголовок похож на TLS. HTTPS/TLS в этой версии не расшифровывается.\nИсходные байты доступны в HEX.";
        String note = original.length > previewLimit ? "Показаны первые " + size(previewLimit) + ". Все исходные байты остаются в сеансе.\n\n" : "";
        byte[] data = Arrays.copyOf(original, Math.min(original.length, previewLimit));
        if (original.length > 4 && Integer.toUnsignedLong(ByteBuffer.wrap(original).getInt()) == original.length - 4) {
            data = data.length > 4 ? Arrays.copyOfRange(data, 4, data.length) : new byte[0];
            note += "Префикс длины 4 байта (формат тестового TCP-клиента).\n\n";
        }
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(data)).toString();
        } catch (CharacterCodingException e) {
            return note + "Бинарные данные или неполная последовательность UTF-8. Смотрите HEX.";
        }
        if (text.codePoints().anyMatch(c -> Character.isISOControl(c) && c != '\r' && c != '\n' && c != '\t'))
            return note + "Бинарные данные. Смотрите HEX.";
        text = text.replace("\r\n", "\n");
        try { var parsed = JSON.readTree(text); if (parsed != null && !parsed.isMissingNode()) return note + JSON.writerWithDefaultPrettyPrinter().writeValueAsString(parsed); }
        catch (Exception ignored) { /* Plain text/HTTP is useful without JSON interpretation. */ }
        int separator = text.indexOf("\n\n");
        if (separator >= 0 && text.matches("(?s)^(HTTP/|GET |POST |PUT |PATCH |DELETE |HEAD ).*")) {
            String body = text.substring(separator + 2);
            try { var parsed = JSON.readTree(body); if (parsed != null && !parsed.isMissingNode()) body = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(parsed); }
            catch (Exception ignored) {}
            return note + text.substring(0, separator) + "\n\n" + body;
        }
        return note + text;
    }
}
