package dbglink.ghidra;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigDecimal;
import java.util.HashSet;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import static dbglink.ghidra.GhidraBridgeServer.*;

final class GhidraRequestParser {
    static JsonObject parseRequest(String line) throws IOException, BridgeFailure {
        JsonReader reader = new JsonReader(new StringReader(line));
        reader.setLenient(false);
        JsonElement parsed = readJsonValue(reader, 0);
        if (!parsed.isJsonObject()) {
            throw new BridgeFailure("invalid_request", "request must be a JSON object");
        }
        if (reader.peek() != JsonToken.END_DOCUMENT) {
            throw new BridgeFailure("invalid_json", "request contains trailing data");
        }
        return parsed.getAsJsonObject();
    }

    private static JsonElement readJsonValue(JsonReader reader, int depth) throws IOException, BridgeFailure {
        if (depth > MAX_JSON_DEPTH) {
            throw new BridgeFailure("invalid_json", "request nesting exceeds the depth limit");
        }

        return switch (reader.peek()) {
            case BEGIN_OBJECT -> {
                reader.beginObject();
                JsonObject object = new JsonObject();
                Set<String> names = new HashSet<>();
                int entries = 0;
                while (reader.hasNext()) {
                    if (entries++ >= MAX_JSON_CONTAINER_ENTRIES) {
                        throw new BridgeFailure("invalid_json", "request object has too many fields");
                    }
                    String name = reader.nextName();
                    if (!names.add(name)) {
                        throw new BridgeFailure("invalid_json", "request contains a duplicate field");
                    }
                    object.add(name, readJsonValue(reader, depth + 1));
                }
                reader.endObject();
                yield object;
            }
            case BEGIN_ARRAY -> {
                reader.beginArray();
                JsonArray array = new JsonArray();
                int entries = 0;
                while (reader.hasNext()) {
                    if (entries++ >= MAX_JSON_CONTAINER_ENTRIES) {
                        throw new BridgeFailure("invalid_json", "request array has too many entries");
                    }
                    array.add(readJsonValue(reader, depth + 1));
                }
                reader.endArray();
                yield array;
            }
            case STRING -> new JsonPrimitive(reader.nextString());
            case BOOLEAN -> new JsonPrimitive(reader.nextBoolean());
            case NULL -> {
                reader.nextNull();
                yield JsonNull.INSTANCE;
            }
            case NUMBER -> {
                String number = reader.nextString();
                if (number.length() > 128) {
                    throw new BridgeFailure("invalid_json", "numeric value exceeds the limit");
                }
                try {
                    yield new JsonPrimitive(new BigDecimal(number));
                }
                catch (NumberFormatException exception) {
                    throw new BridgeFailure("invalid_json", "numeric value is malformed");
                }
            }
            default -> throw new BridgeFailure("invalid_json", "request contains an invalid JSON value");
        };
    }

}
