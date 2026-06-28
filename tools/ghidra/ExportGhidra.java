// Ghidra headless post-script (Java — works without PyGhidra/Jython).
// Exports a triage-focused JSON from an analyzed program. Invoked as:
//   analyzeHeadless <proj> <name> -import SAMPLE -scriptPath tools/ghidra \
//       -postScript ExportGhidra.java <out.json>
//
// Design (see analyze-sample SKILL.md): do NOT dump every function. Export full metadata +
// function inventory + imports + strings always, but decompile only a TARGETED shortlist
// (entry point + functions referencing network/crypto/loader imports), capped, so the JSON
// stays small enough to reason over.
//@category Triage

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;

public class ExportGhidra extends GhidraScript {

    static final int MAX_DECOMP     = 30;
    static final int MAX_C_CHARS    = 8000;
    static final int MAX_STRINGS    = 4000;
    static final int DECOMP_TIMEOUT = 60;

    static final String[] INTERESTING = {
        "socket","connect","send","recv","bind","listen","accept","gethostbyname",
        "internet","wininet","httpopen","urldownload",
        "crypt","xor","decrypt","rc4","aes","base64",
        "virtualalloc","virtualprotect","globalalloc","heapalloc","localalloc","mapviewoffile",
        "writefile","readfile","createfile","fopen","fwrite","fread","getmodulefilename",
        "createprocess","winexec","shellexecute","createthread","createremotethread",
        "getprocaddress","loadlibrary","regsetvalue","regopenkey","regcreatekey",
        "createmutex","setfileattributes","copyfile","movefile","deletefile",
        "isdebuggerpresent","gettickcount","cpuid"
    };

    private boolean isInteresting(String name) {
        if (name == null) return false;
        String n = name.toLowerCase();
        for (String s : INTERESTING) if (n.contains(s)) return true;
        return false;
    }

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n");  break;
                case '\r': b.append("\\r");  break;
                case '\t': b.append("\\t");  break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }
    private static String q(String s) { return "\"" + esc(s) + "\""; }
    private static String hex(Address a) { return a == null ? "null" : "0x" + Long.toHexString(a.getOffset()); }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = (args != null && args.length > 0) ? args[0] : "ghidra.json";

        Program prog = currentProgram;
        Listing listing = prog.getListing();
        FunctionManager fm = prog.getFunctionManager();
        List<String> notes = new ArrayList<>();

        // entry point
        Address entryAddr = null;
        Function entryFunc = null;
        var it = prog.getSymbolTable().getExternalEntryPointIterator();
        if (it.hasNext()) {
            entryAddr = it.next();
            entryFunc = fm.getFunctionContaining(entryAddr);
        }

        StringBuilder j = new StringBuilder();
        j.append("{\n");
        j.append("  \"tool\": \"ghidra-headless\",\n");
        j.append("  \"program\": {\n");
        j.append("    \"name\": ").append(q(prog.getName())).append(",\n");
        j.append("    \"sha256\": ").append(q(prog.getExecutableSHA256())).append(",\n");
        j.append("    \"md5\": ").append(q(prog.getExecutableMD5())).append(",\n");
        j.append("    \"format\": ").append(q(prog.getExecutableFormat())).append(",\n");
        j.append("    \"language\": ").append(q(prog.getLanguageID().toString())).append(",\n");
        j.append("    \"image_base\": ").append(q(hex(prog.getImageBase()))).append(",\n");
        j.append("    \"entry_point\": ").append(q(entryAddr == null ? "" : hex(entryAddr))).append(",\n");
        j.append("    \"function_count\": ").append(fm.getFunctionCount()).append("\n");
        j.append("  },\n");

        // imports
        j.append("  \"imports\": [\n");
        ExternalManager em = prog.getExternalManager();
        boolean first = true;
        try {
            for (String lib : em.getExternalLibraryNames()) {
                ExternalLocationIterator li = em.getExternalLocations(lib);
                while (li.hasNext()) {
                    ExternalLocation loc = li.next();
                    if (!first) j.append(",\n");
                    first = false;
                    j.append("    {\"library\": ").append(q(lib))
                     .append(", \"name\": ").append(q(loc.getLabel())).append("}");
                }
            }
        } catch (Exception e) { notes.add("import enumeration error: " + e); }
        j.append("\n  ],\n");

        // function inventory + decompile candidates
        List<Function> candidates = new ArrayList<>();
        Map<Function, Integer> prio = new HashMap<>();

        j.append("  \"functions\": [\n");
        first = true;
        for (Function f : fm.getFunctions(true)) {
            if (monitor.isCancelled()) break;
            List<String> calls = new ArrayList<>();
            try {
                for (Function cf : f.getCalledFunctions(monitor)) {
                    if (isInteresting(cf.getName())) calls.add(cf.getName());
                }
            } catch (Exception ignore) {}
            TreeSet<String> uniq = new TreeSet<>(calls);

            if (!first) j.append(",\n");
            first = false;
            j.append("    {\"name\": ").append(q(f.getName()))
             .append(", \"entry\": ").append(q(hex(f.getEntryPoint())))
             .append(", \"size\": ").append(f.getBody().getNumAddresses())
             .append(", \"is_thunk\": ").append(f.isThunk())
             .append(", \"interesting_calls\": [");
            boolean cf2 = true;
            for (String c : uniq) { if (!cf2) j.append(", "); cf2 = false; j.append(q(c)); }
            j.append("]}");

            if (entryFunc != null && f.equals(entryFunc)) { candidates.add(f); prio.put(f, 10000); }
            else if (!uniq.isEmpty()) { candidates.add(f); prio.put(f, 1000 + uniq.size()); }
        }
        j.append("\n  ],\n");

        // top up shortlist with largest non-thunk functions
        if (candidates.size() < MAX_DECOMP) {
            List<Function> bySize = new ArrayList<>();
            for (Function f : fm.getFunctions(true)) if (!f.isThunk()) bySize.add(f);
            bySize.sort((a, b) -> Long.compare(b.getBody().getNumAddresses(), a.getBody().getNumAddresses()));
            for (Function f : bySize) {
                if (candidates.size() >= MAX_DECOMP) break;
                if (!prio.containsKey(f)) { candidates.add(f); prio.put(f, 1); }
            }
        }
        candidates.sort((a, b) -> Integer.compare(prio.get(b), prio.get(a)));
        if (candidates.size() > MAX_DECOMP) candidates = candidates.subList(0, MAX_DECOMP);

        // decompile shortlist
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(prog);
        j.append("  \"decompiled\": [\n");
        first = true;
        for (Function f : candidates) {
            if (monitor.isCancelled()) break;
            try {
                DecompileResults res = ifc.decompileFunction(f, DECOMP_TIMEOUT, monitor);
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    String c = res.getDecompiledFunction().getC();
                    boolean trunc = false;
                    if (c != null && c.length() > MAX_C_CHARS) { c = c.substring(0, MAX_C_CHARS) + "\n/* ...truncated... */"; trunc = true; }
                    if (!first) j.append(",\n");
                    first = false;
                    j.append("    {\"name\": ").append(q(f.getName()))
                     .append(", \"entry\": ").append(q(hex(f.getEntryPoint())))
                     .append(", \"truncated\": ").append(trunc)
                     .append(", \"c\": ").append(q(c)).append("}");
                }
            } catch (Exception e) { notes.add("decompile error " + f.getName() + ": " + e); }
        }
        ifc.dispose();
        j.append("\n  ],\n");

        // defined strings
        j.append("  \"strings\": [\n");
        first = true;
        int count = 0;
        for (Data d : listing.getDefinedData(true)) {
            if (count >= MAX_STRINGS || monitor.isCancelled()) break;
            try {
                String dt = d.getDataType().getName().toLowerCase();
                if (dt.contains("unicode") || dt.contains("string")) {
                    String val = d.getDefaultValueRepresentation();
                    if (val != null && !val.isEmpty()) {
                        if (!first) j.append(",\n");
                        first = false;
                        j.append("    {\"addr\": ").append(q(hex(d.getAddress())))
                         .append(", \"value\": ").append(q(val)).append("}");
                        count++;
                    }
                }
            } catch (Exception ignore) {}
        }
        j.append("\n  ],\n");

        // notes
        j.append("  \"notes\": [");
        for (int i = 0; i < notes.size(); i++) { if (i > 0) j.append(", "); j.append(q(notes.get(i))); }
        j.append("]\n}\n");

        try (Writer w = new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8)) {
            w.write(j.toString());
        }
        println("[ExportGhidra] wrote " + fm.getFunctionCount() + " functions, "
                + candidates.size() + " decompiled, " + count + " strings -> " + out);
    }
}
