// Headless integration check against tests/fixtures/AnalysisTarget.exe.
// Pass the freshly packaged GhidraBridge.jar as the script's sole argument.
// @category DBGLink
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.*;
import com.google.gson.*;
import java.net.*;
import java.nio.file.*;
import java.lang.reflect.*;
import java.util.function.Supplier;

public class StaticBridgeChecks extends GhidraScript {
    private Object queries;
    private Method execute;
    private JsonObject query(String method, String json) throws Exception {
        return (JsonObject)execute.invoke(queries, method, JsonParser.parseString(json).getAsJsonObject());
    }
    private void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
    @Override public void run() throws Exception {
        try (URLClassLoader loader = new URLClassLoader(new URL[] {Path.of(getScriptArgs()[0]).toUri().toURL()}, Program.class.getClassLoader())) {
            Class<?> type = loader.loadClass("dbglink.ghidra.GhidraStaticQueries");
            var constructor = type.getDeclaredConstructor(Supplier.class); constructor.setAccessible(true);
            queries = constructor.newInstance((Supplier<Program>)() -> currentProgram);
            execute = type.getDeclaredMethod("execute", String.class, JsonObject.class); execute.setAccessible(true);
            JsonObject strings = query("DumpStrings", "{\"filter\":\"DBGLink\",\"includeHex\":true}");
            check(!strings.getAsJsonArray("strings").isEmpty(), "Fixture string not found without debugger");
            JsonObject first = strings.getAsJsonArray("strings").get(0).getAsJsonObject();
            String address = first.get("address").getAsString();
            int byteLength = first.get("hex").getAsString().length() / 2;
            JsonObject bytes = query("ReadStaticBytes", "{\"address\":\"" + address + "\",\"length\":" + byteLength + "}");
            check(bytes.get("hex").equals(first.get("hex")), "DumpStrings bytes differ from ReadStaticBytes");
            check(!query("XrefsTo", "{\"address\":\"" + address + "\"}").getAsJsonArray("references").isEmpty(), "String-to-data reference missing");
            check(!query("ListImports", "{\"filter\":\"GetCurrentProcessId\"}").getAsJsonArray("imports").isEmpty(), "Known PE import missing");
            check(query("ListExports", "{\"filter\":\"Fixture*\"}").getAsJsonArray("exports").size() >= 3, "PE exports missing");
            Function caller = currentProgram.getListing().getGlobalFunctions("FixtureCaller").get(0);
            Function callee = currentProgram.getListing().getGlobalFunctions("FixtureCallee").get(0);
            JsonArray refs = query("XrefsTo", "{\"address\":\"" + callee.getEntryPoint() + "\",\"callsOnly\":true}").getAsJsonArray("references");
            check(!refs.isEmpty(), "Caller-to-callee reference missing");
            check(refs.get(0).getAsJsonObject().has("function"), "Containing function missing");
            String range = "{\"start\":\"" + caller.getEntryPoint().add(1) + "\",\"end\":\"" + caller.getEntryPoint().add(2) + "\"}";
            check(query("ListFunctions", range).getAsJsonArray("functions").size() == 1, "Body intersection missing");

            // Defining over an address that already has a function is a no-op,
            // not a duplicate or an error.
            Class<?> operationsType = loader.loadClass("dbglink.ghidra.GhidraAnalysisOperations");
            var operationsConstructor = operationsType.getDeclaredConstructor(Supplier.class);
            operationsConstructor.setAccessible(true);
            Object operations = operationsConstructor.newInstance((Supplier<Program>)() -> currentProgram);
            Method createFunction = operationsType.getDeclaredMethod("createFunction", JsonObject.class);
            createFunction.setAccessible(true);
            JsonObject defined = (JsonObject)createFunction.invoke(operations, JsonParser.parseString(
                "{\"address\":\"" + caller.getEntryPoint() + "\"}").getAsJsonObject());
            check(defined.get("alreadyDefined").getAsBoolean(), "Existing function not reported as alreadyDefined");
            check(!defined.get("committed").getAsBoolean(), "Already-defined function reported as a commit");

            // Resolve a real high-level parameter, then exercise the decompiler-to-database rename path.
            DecompInterface decompiler = new DecompInterface();
            String variable;
            try {
                check(decompiler.openProgram(currentProgram), "Decompiler open failed");
                var decoded = decompiler.decompileFunction(caller, 30, monitor);
                check(decoded.decompileCompleted(), "Fixture decompilation failed");
                variable = decoded.getHighFunction().getLocalSymbolMap().getParamSymbol(0).getName();
            } finally { decompiler.dispose(); }
            Class<?> decoderType = loader.loadClass("dbglink.ghidra.GhidraDecompiler");
            var decoderCtor = decoderType.getDeclaredConstructor(); decoderCtor.setAccessible(true);
            var rename = decoderType.getDeclaredMethod("renameDecompilerVariable", Program.class, Function.class, String.class, String.class);
            rename.setAccessible(true);
            JsonObject renamed;
            int transaction = currentProgram.startTransaction("StaticBridgeChecks rename");
            boolean committed = false;
            try {
                renamed = (JsonObject)rename.invoke(decoderCtor.newInstance(), currentProgram, caller, variable, "mixerInput");
                committed = true;
            } finally {
                currentProgram.endTransaction(transaction, committed);
            }
            check("mixerInput".equals(renamed.get("name").getAsString()), "Decompiler variable rename result was not applied");
            check(java.util.Arrays.stream(caller.getAllVariables()).anyMatch(v -> v.getName().equals("mixerInput")), "Renamed variable not in program database");
            println("STATIC_BRIDGE_INTEGRATION_PASS " + currentProgram.getLanguageID());
        }
    }
}
