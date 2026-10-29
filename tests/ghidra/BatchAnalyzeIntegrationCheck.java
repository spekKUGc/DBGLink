// Headless integration check for AnalyzeFunctions + BatchAnnotate against
// tests/fixtures/AnalysisTarget.exe: import, analyzeFunctions over the two
// fixture functions (decompilation, references, strings, constants), then a
// BatchAnnotate batch (rename + comment + one conflicting rename).
// Pass the freshly packaged GhidraBridge.jar as the script's sole argument.
// @category DBGLink
//
// Run (Ghidra 12.x, PowerShell):
//   $GH = "<ghidraInstallDir>"; $T = "<worktree>"; $F = "<AnalysisTarget.exe>"
//   & "$GH\support\analyzeHeadless.bat" "$T\proj" BatchCheck -import "$F" `
//     -scriptPath "<repo>\tests\ghidra" -postScript BatchAnalyzeIntegrationCheck.java "<bridgeJar>" -deleteProject
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import com.google.gson.*;
import java.net.*;
import java.nio.file.*;
import java.lang.reflect.*;
import java.util.function.Supplier;

public class BatchAnalyzeIntegrationCheck extends GhidraScript {
    private Object operations;
    private Method analyze;
    private Method batch;

    private JsonObject analyzeFunctions(String json) throws Exception {
        return (JsonObject) analyze.invoke(operations, JsonParser.parseString(json).getAsJsonObject());
    }

    private JsonObject batchAnnotate(String json) throws Exception {
        return (JsonObject) batch.invoke(operations, JsonParser.parseString(json).getAsJsonObject());
    }

    private void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    @Override public void run() throws Exception {
        try (URLClassLoader loader = new URLClassLoader(new URL[] { Path.of(getScriptArgs()[0]).toUri().toURL() },
                Program.class.getClassLoader())) {
            Class<?> operationsType = loader.loadClass("dbglink.ghidra.GhidraAnalysisOperations");
            var constructor = operationsType.getDeclaredConstructor(Supplier.class);
            constructor.setAccessible(true);
            operations = constructor.newInstance((Supplier<Program>) () -> currentProgram);
            analyze = operationsType.getDeclaredMethod("analyzeFunctions", JsonObject.class);
            analyze.setAccessible(true);
            batch = operationsType.getDeclaredMethod("batchAnnotate", JsonObject.class);
            batch.setAccessible(true);

            // 1. Digest of the two fixture functions: slim identity (module
            // hoists to the envelope), decompilation, brief references,
            // referenced strings and significant constants.
            JsonObject digest = analyzeFunctions("{\"functions\":[\"FixtureCaller\",\"FixtureCallee\"]}");
            check(digest.has("module"), "AnalyzeFunctions lost its hoisted module identity");
            JsonArray entries = digest.getAsJsonArray("functions");
            check(entries.size() == 2, "Expected two analyzed functions, got " + entries.size());
            int strings = 0;
            int constants = 0;
            for (int index = 0; index < entries.size(); index++) {
                JsonObject entry = entries.get(index).getAsJsonObject();
                check(!entry.has("ok") || entry.get("ok").getAsBoolean(), "AnalyzeFunctions entry " + index + " failed");
                check(!entry.has("selector") && !entry.has("index"), "AnalyzeFunctions entry " + index + " not slim");
                check(entry.has("function"), "AnalyzeFunctions entry " + index + " lost identity");
                check(entry.getAsJsonObject("decompilation").get("status").getAsString().equals("ok"),
                    "AnalyzeFunctions entry " + index + " lost decompilation");
                check(entry.has("references"), "AnalyzeFunctions entry " + index + " lost references");
                check(entry.get("strings").isJsonArray(),
                    "AnalyzeFunctions entry " + index + " lost strings");
                check(entry.get("constants").isJsonArray(),
                    "AnalyzeFunctions entry " + index + " lost constants");
                strings += entry.getAsJsonArray("strings").size();
                constants += entry.getAsJsonArray("constants").size();
            }
            println("BATCH_ANALYZE digest functions=2 strings=" + strings + " constants=" + constants);
            check(strings > 0, "Fixture digest lost referenced strings");
            check(constants > 0, "Fixture digest lost constants");

            // Caller references the callee; the callee digest must name it.
            JsonObject callee = entries.get(1).getAsJsonObject();
            boolean callerSeen = false;
            for (JsonElement row : callee.getAsJsonObject("references").getAsJsonArray("callers")) {
                if (row.getAsJsonObject().get("name").getAsString().equals("FixtureCaller")) callerSeen = true;
            }
            check(callerSeen, "Callee digest lost FixtureCaller");

            // 2. Batch: rename the caller, comment the callee, then collide
            // with the fresh name. The conflict must fail by index while the
            // other two operations still commit.
            JsonObject annotated = batchAnnotate("{\"operations\":["
                + "{\"kind\":\"rename_function\",\"function\":\"FixtureCaller\",\"name\":\"W08RenamedCaller\"},"
                + "{\"kind\":\"set_function_comment\",\"function\":\"FixtureCallee\",\"comment\":\"w08 integration\"},"
                + "{\"kind\":\"rename_function\",\"function\":\"FixtureCallee\",\"name\":\"W08RenamedCaller\"}]}");
            check(annotated.get("applied").getAsInt() == 2, "BatchAnnotate applied != 2");
            check(annotated.get("failed").getAsInt() == 1, "BatchAnnotate failed != 1");
            JsonArray results = annotated.getAsJsonArray("results");
            check(results.size() == 3, "BatchAnnotate lost per-index rows");
            check(results.get(0).getAsJsonObject().get("ok").getAsBoolean(), "Batch rename lost");
            check(results.get(1).getAsJsonObject().get("ok").getAsBoolean(), "Batch comment lost");
            JsonObject conflict = results.get(2).getAsJsonObject();
            check(!conflict.get("ok").getAsBoolean(), "Conflicting rename unexpectedly committed");
            check(conflict.get("code").getAsString().equals("mutation_conflict"),
                "Conflict code is not mutation_conflict: " + conflict.get("code"));

            // The surviving mutations must be visible in the program database.
            check(!currentProgram.getListing().getGlobalFunctions("W08RenamedCaller").isEmpty(),
                "Renamed caller not in program database");
            Function commented = currentProgram.getListing().getGlobalFunctions("FixtureCallee").get(0);
            check("w08 integration".equals(commented.getComment()), "Comment not in program database");

            println("BATCH_ANALYZE_INTEGRATION_PASS strings=" + strings + " constants=" + constants
                + " applied=2 failed=1");
        }
    }
}
