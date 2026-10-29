package dbglink.ghidra;

import java.util.LinkedHashSet;
import java.util.Set;
import com.google.gson.JsonArray;

final class GhidraOutputBudget {
    private static final int RESERVED_RESPONSE_BYTES = 64 * 1024;
    private static final int MAX_CONTENT_BYTES =
        GhidraBridgeServer.MAX_RESPONSE_BYTES - RESERVED_RESPONSE_BYTES;
    private static final int ELLIPSIS_BYTES = jsonStringLength("…");

    int remaining;
    boolean truncated;
    private final Set<String> truncatedSections = new LinkedHashSet<>();
    private int remainingBytes;

    GhidraOutputBudget(int maxChars) {
        remaining = maxChars;
        remainingBytes = MAX_CONTENT_BYTES;
    }

    void markTruncated(String section) {
        truncated = true;
        truncatedSections.add(section);
    }

    JsonArray truncatedSections() {
        JsonArray result = new JsonArray();
        truncatedSections.forEach(result::add);
        return result;
    }

    String take(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }

        int valueBytes = value.length() <= remaining
            ? jsonStringLengthUpTo(value, remainingBytes)
            : remainingBytes + 1;
        if (value.length() <= remaining && valueBytes <= remainingBytes) {
            remaining -= value.length();
            remainingBytes -= valueBytes;
            return value;
        }

        markTruncated("outputBudget");
        int maxPrefixChars = Math.min(Math.max(remaining - 1, 0), value.length());
        int maxPrefixBytes = Math.max(remainingBytes - ELLIPSIS_BYTES, 0);
        int prefixChars = 0;
        int prefixBytes = 0;
        while (prefixChars < maxPrefixChars) {
            int codePoint = value.codePointAt(prefixChars);
            int codePointChars = Character.charCount(codePoint);
            int codePointBytes = jsonStringLength(codePoint);
            if (prefixChars + codePointChars > maxPrefixChars
                || prefixBytes + codePointBytes > maxPrefixBytes) {
                break;
            }
            prefixChars += codePointChars;
            prefixBytes += codePointBytes;
        }

        if (prefixChars == 0) {
            remaining = 0;
            remainingBytes = 0;
            return "";
        }

        remaining = 0;
        remainingBytes = 0;
        return value.substring(0, prefixChars) + "…";
    }

    private static int jsonStringLength(String value) {
        int bytes = 0;
        for (int offset = 0; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            bytes += jsonStringLength(codePoint);
            offset += Character.charCount(codePoint);
        }
        return bytes;
    }

    private static int jsonStringLengthUpTo(String value, int maxBytes) {
        int bytes = 0;
        for (int offset = 0; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            int codePointBytes = jsonStringLength(codePoint);
            if (codePointBytes > maxBytes - bytes) {
                return maxBytes + 1;
            }
            bytes += codePointBytes;
            offset += Character.charCount(codePoint);
        }
        return bytes;
    }

    private static int jsonStringLength(int codePoint) {
        if (codePoint == '"' || codePoint == '\\' ||
            codePoint == '\b' || codePoint == '\f' ||
            codePoint == '\n' || codePoint == '\r' || codePoint == '\t') {
            return 2;
        }
        if (codePoint <= 0x1F) {
            return 6;
        }
        if (codePoint <= 0x7F) {
            return 1;
        }
        if (codePoint <= 0x7FF) {
            return 2;
        }
        if (codePoint <= 0xFFFF) {
            return 3;
        }
        return 4;
    }
}
