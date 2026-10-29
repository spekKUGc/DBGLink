// Token-efficiency benchmark against tests/fixtures/AnalysisTarget.exe.
// Measures naive (default budgets) vs optimized (tight budgets) static-query
// payloads with real bridge responses, plus the coverage/rva-trim patch delta.
// Tokens are real cl100k_base BPE counts via jtokkit (com.knuddels:jtokkit),
// matching the .NET side (Microsoft.ML.Tokenizers cl100k_base,
// tests/DbgLink.Tests/TokenCounter.cs). The tokenizer is the single source of
// truth in this script (see tokens()/ensureTokenizer()).
//
// Run (Ghidra 12.x, PowerShell):
//   $GH = "<ghidraInstallDir>"; $T = "<workdir>"
//   & "$GH\support\analyzeHeadless.bat" "$T\proj" Bench -import "$T\AnalysisTarget.exe" `
//     -scriptPath "<repo>\tests\ghidra" -postScript TokenEfficiencyBenchmark.java "<bridgeJar>" ["<jtokkitJar>"] -deleteProject
// Pass the freshly packaged GhidraBridge.jar as the script's first argument.
// The jtokkit jar (e.g. com.knuddels:jtokkit:1.1.0 from Maven Central) may be
// passed as an optional second argument; if it is already on the Ghidra
// classpath the second argument can be omitted. jtokkit is loaded
// reflectively so Ghidra's standalone script compiler needs no extra
// compile-time dependency, and the Ghidra extension build file is
// intentionally left untouched.
// @category DBGLink
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import com.google.gson.*;
import java.net.*;
import java.nio.file.*;
import java.lang.reflect.*;
import java.util.function.Supplier;

public class TokenEfficiencyBenchmark extends GhidraScript {
    private Object queries;
    private Object operations;
    private long totalNaiveChars = 0;
    private long totalOptChars = 0;
    private long totalNaiveTokens = 0;
    private long totalOptTokens = 0;

    // Single source of truth for token counting: one lazily created cl100k_base
    // Encoding, resolved reflectively (see header for how jtokkit is supplied).
    private static volatile Object cl100kEncoding;
    private static volatile Method cl100kEncode;
    private static final Object TOKENIZER_GATE = new Object();

    private static void ensureTokenizer(String[] args) throws Exception {
        if (cl100kEncoding != null) return;
        synchronized (TOKENIZER_GATE) {
            if (cl100kEncoding != null) return;
            ClassLoader loader = TokenEfficiencyBenchmark.class.getClassLoader();
            Class<?> encodings = null;
            try {
                encodings = Class.forName("com.knuddels.jtokkit.Encodings", true, loader);
            } catch (ClassNotFoundException notOnClasspath) {
                if (args.length < 2)
                    throw new IllegalStateException(
                        "jtokkit not on classpath: pass the jtokkit jar (com.knuddels:jtokkit) "
                        + "as the second script argument after the bridge jar, "
                        + "or add it to the Ghidra classpath.");
                loader = new URLClassLoader(new URL[] { Path.of(args[1]).toUri().toURL() },
                    TokenEfficiencyBenchmark.class.getClassLoader());
                encodings = Class.forName("com.knuddels.jtokkit.Encodings", true, loader);
            }
            Object registry = encodings.getMethod("newDefaultEncodingRegistry").invoke(null);
            Class<?> encodingType = Class.forName("com.knuddels.jtokkit.api.EncodingType", true, loader);
            Object cl100kBase = encodingType.getField("CL100K_BASE").get(null);
            Object encoding = registry.getClass().getMethod("getEncoding", encodingType).invoke(registry, cl100kBase);
            cl100kEncode = encoding.getClass().getMethod("encode", String.class);
            cl100kEncoding = encoding;
        }
    }

    private static long tokens(String s) throws Exception {
        if (s.isEmpty()) return 0;
        Object encoded = cl100kEncode.invoke(cl100kEncoding, s);
        return ((Number) encoded.getClass().getMethod("size").invoke(encoded)).longValue();
    }

    private JsonObject query(String method, String json) throws Exception {
        Method m = queries.getClass().getDeclaredMethod("execute", String.class, JsonObject.class);
        m.setAccessible(true);
        return (JsonObject) m.invoke(queries, method, JsonParser.parseString(json).getAsJsonObject());
    }

    private JsonObject inspect(String json) throws Exception {
        Method target = null;
        for (Method m : operations.getClass().getDeclaredMethods())
            if (m.getName().equals("inspectFunction")) target = m;
        target.setAccessible(true);
        return (JsonObject) target.invoke(operations, JsonParser.parseString(json).getAsJsonObject());
    }

    private void check(boolean value, String message) throws Exception {
        if (!value) throw new AssertionError(message);
    }

    private void scenario(String name, String naive, String opt, boolean optMayTruncate) throws Exception {
        long n = naive.length(), o = opt.length();
        check(o <= n, name + ": optimized payload larger than naive");
        totalNaiveChars += n;
        totalOptChars += o;
        long naiveTokens = tokens(naive), optTokens = tokens(opt);
        totalNaiveTokens += naiveTokens;
        totalOptTokens += optTokens;
        double factor = (double) n / Math.max(1, o);
        double saved = 100.0 * (n - o) / Math.max(1, n);
        println(String.format("BENCH %-14s naive=%6dB/%4dtok opt=%6dB/%4dtok %5.1fx %5.1f%%",
            name, n, naiveTokens, o, optTokens, factor, saved));
    }

    @Override public void run() throws Exception {
        ensureTokenizer(getScriptArgs());
        try (URLClassLoader loader = new URLClassLoader(new URL[] { Path.of(getScriptArgs()[0]).toUri().toURL() },
                Program.class.getClassLoader())) {
            Class<?> qType = loader.loadClass("dbglink.ghidra.GhidraStaticQueries");
            var qCtor = qType.getDeclaredConstructor(Supplier.class); qCtor.setAccessible(true);
            queries = qCtor.newInstance((Supplier<Program>)() -> currentProgram);
            Class<?> oType = loader.loadClass("dbglink.ghidra.GhidraAnalysisOperations");
            var oCtor = oType.getDeclaredConstructors()[0]; oCtor.setAccessible(true);
            operations = oCtor.newInstance((Supplier<Program>)() -> currentProgram);

            Function caller = currentProgram.getListing().getGlobalFunctions("FixtureCaller").get(0);
            Function callee = currentProgram.getListing().getGlobalFunctions("FixtureCallee").get(0);

            // S1: function index — full range vs name-filtered slice.
            JsonObject idxNaive = query("ListFunctions", "{}");
            JsonObject idxOpt = query("ListFunctions", "{\"filter\":\"Fixture\",\"maxItems\":16}");
            check(idxOpt.getAsJsonArray("functions").size() >= 2, "S1 lost fixture functions");
            scenario("index", idxNaive.toString(), idxOpt.toString(), true);

            // S2: inspect with default 24k budget vs 6k triage budget (same sections).
            JsonObject insNaive = inspect("{\"function\":\"FixtureCaller\"}");
            JsonObject insOpt = inspect("{\"function\":\"FixtureCaller\",\"maxChars\":6000,\"maxItems\":10}");
            check(insOpt.has("decompilation") && insOpt.has("references"), "S2 lost sections");
            scenario("inspect", insNaive.toString(), insOpt.toString(), true);

            // S3: "who calls this" needs no decompilation.
            JsonObject refNaive = inspect("{\"function\":\"FixtureCallee\"}");
            JsonObject refOpt = inspect("{\"function\":\"FixtureCallee\",\"includeDecomp\":false}");
            check(refOpt.has("references") && !refOpt.has("decompilation"), "S3 shape wrong");
            scenario("refs-only", refNaive.toString(), refOpt.toString(), false);

            // S4: string dump — whole image vs narrowed section+filter slice.
            JsonObject strNaive = query("DumpStrings", "{}");
            JsonObject strOpt = query("DumpStrings", "{\"section\":\".rdata\",\"filter\":\"DBGLink\",\"maxItems\":16}");
            check(!strOpt.getAsJsonArray("strings").isEmpty(), "S4 lost fixture strings");
            scenario("strings", strNaive.toString(), strOpt.toString(), true);

            // S5: xrefs — all refs vs direct calls only.
            JsonObject xNaive = query("XrefsTo", "{\"address\":\"" + callee.getEntryPoint() + "\"}");
            JsonObject xOpt = query("XrefsTo", "{\"address\":\"" + callee.getEntryPoint() + "\",\"callsOnly\":true}");
            check(!xOpt.getAsJsonArray("references").isEmpty(), "S5 lost call refs");
            scenario("xrefs", xNaive.toString(), xOpt.toString(), false);

            // S6: imports — full 32-site rows vs default refCount rows (same rows, honest flag).
            JsonObject iNaive = query("ListImports", "{\"maxSites\":32}");
            JsonObject iOpt = query("ListImports", "{}");
            check(iOpt.has("truncated"), "S6 lost truncation flag");
            check(iOpt.getAsJsonArray("imports").size() == iNaive.getAsJsonArray("imports").size(), "S6 lost rows");
            scenario("imports", iNaive.toString(), iOpt.toString(), true);

            // S7: patch delta on the optimized workflow (byte-exact reconstruction:
            // coverage was the last-added property; module.rva duplicates function.rva).
            StringBuilder patch = new StringBuilder();
            patch.append(coverageFragment("Ghidra reference database; unresolved indirect references are not inferred"));
            patch.append(coverageFragment("Ghidra reference database; outgoing references from target address/function"));
            patch.append(coverageFragment("Ghidra external symbols; refCount always travels, referenceSites opt-in via includeSites"));
            patch.append(coverageFragment("Printable ASCII and UTF-16LE ASCII-range strings in initialized non-executable blocks, or the explicit section; hex excludes terminators"));
            patch.append(",\"rva\":\"").append(insOpt.getAsJsonObject("function").get("rva").getAsString()).append("\"}");
            // (ListFunctions/ListExports carry no coverage; index slice counted once for imports-equivalent.)
            long patchChars = patch.length();
            long patchTokens = tokens(patch.toString());
            long before = totalOptChars + patchChars;
            double factor = (double) before / Math.max(1, totalOptChars);
            println(String.format("BENCH %-14s naive=%6dB/%4dtok opt=%6dB/%4dtok %5.1fx %5.1f%%",
                "patch-trim", before, totalOptTokens + patchTokens,
                totalOptChars, totalOptTokens, factor,
                100.0 * patchChars / before));

            double aggFactor = (double) totalNaiveChars / Math.max(1, totalOptChars);
            double aggSaved = 100.0 * (totalNaiveChars - totalOptChars) / Math.max(1, totalNaiveChars);
            println(String.format("BENCH-AGGREGATE naive=%dB/%dtok opt=%dB/%dtok %.1fx %.1f%% saved",
                totalNaiveChars, totalNaiveTokens,
                totalOptChars, totalOptTokens, aggFactor, aggSaved));
            println("TOKEN_BENCHMARK_PASS");
        }
    }

    private static String coverageFragment(String literal) {
        // ,"coverage":"<literal>"
        return ",\"coverage\":\"" + literal + "\"";
    }
}
