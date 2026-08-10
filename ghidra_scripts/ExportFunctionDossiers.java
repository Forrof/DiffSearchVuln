// Export complete, deterministic per-function evidence as JSON Lines.
// @category DiffSearchVuln

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class ExportFunctionDossiers extends GhidraScript {
    private static final String SCHEMA_VERSION = "1.0.0";

    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length < 3) {
            throw new IllegalArgumentException(
                "expected output path, artifact sha256, and architecture"
            );
        }
        Path output = Path.of(arguments[0]).toAbsolutePath();
        String artifactSha256 = arguments[1];
        String architecture = arguments[2];
        int maximumFunctions = arguments.length >= 4 ? Integer.parseInt(arguments[3]) : 0;
        int functionTimeoutSeconds = arguments.length >= 5 ? Integer.parseInt(arguments[4]) : 30;
        Path selectionPath = arguments.length >= 6 ? Path.of(arguments[5]).toAbsolutePath() : null;
        validateArchitecture(architecture);

        Files.createDirectories(output.getParent());
        List<Function> selectedFunctions = selectionPath == null
            ? null
            : prepareSelectedFunctions(selectionPath);
        DecompInterface decompiler = createDecompiler();
        int exported = 0;
        int decompileFailures = 0;

        try (BufferedWriter writer = Files.newBufferedWriter(
                output,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            FunctionIterator functions = selectedFunctions == null
                ? currentProgram.getFunctionManager().getFunctions(true)
                : null;
            while ((selectedFunctions == null ? functions.hasNext() : exported < selectedFunctions.size()) &&
                    (maximumFunctions <= 0 || exported < maximumFunctions)) {
                monitor.checkCancelled();
                Function function = selectedFunctions == null
                    ? functions.next()
                    : selectedFunctions.get(exported);
                ExportedFunction record = exportFunction(
                    function,
                    decompiler,
                    functionTimeoutSeconds,
                    artifactSha256,
                    architecture
                );
                if (record.decompilation == null) {
                    decompileFailures++;
                }
                writer.write(record.toJson());
                writer.newLine();
                exported++;
                if (exported % 100 == 0) {
                    writer.flush();
                    println("Exported " + exported + " functions");
                }
            }
        }
        decompiler.dispose();
        println(
            "DIFFSEARCHVULN_EXPORT functions=" + exported +
            " decompile_failures=" + decompileFailures +
            " output=" + output
        );
    }

    private List<Function> prepareSelectedFunctions(Path selectionPath) throws Exception {
        List<Function> selected = new ArrayList<>();
        List<String> lines = Files.readAllLines(selectionPath, StandardCharsets.UTF_8);
        for (int lineNumber = 0; lineNumber < lines.size(); lineNumber++) {
            monitor.checkCancelled();
            String line = lines.get(lineNumber);
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            String[] fields = line.split("\\t", 3);
            if (fields.length < 2) {
                throw new IllegalArgumentException(
                    "invalid selection at line " + (lineNumber + 1) + ": expected start and end"
                );
            }
            Address start = toAddr(fields[0]);
            Address endExclusive = toAddr(fields[1]);
            if (start == null || endExclusive == null || endExclusive.compareTo(start) <= 0) {
                throw new IllegalArgumentException(
                    "invalid address range at selection line " + (lineNumber + 1)
                );
            }
            Address endInclusive = endExclusive.subtract(1);
            AddressSet requestedBody = new AddressSet(start, endInclusive);
            Function function = currentProgram.getFunctionManager().getFunctionAt(start);
            if (function == null) {
                DisassembleCommand disassemble = new DisassembleCommand(start, requestedBody, true);
                disassemble.applyTo(currentProgram, monitor);
                AddressSet instructionBody = new AddressSet();
                InstructionIterator instructions = currentProgram.getListing().getInstructions(
                    requestedBody,
                    true
                );
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next();
                    instructionBody.addRange(
                        instruction.getMinAddress(),
                        instruction.getMaxAddress()
                    );
                }
                if (instructionBody.isEmpty()) {
                    throw new IllegalStateException(
                        "no instructions disassembled for selected function at " + start
                    );
                }
                String fallbackName = "selected_" + start.toString();
                function = currentProgram.getListing().createFunction(
                    fallbackName,
                    start,
                    instructionBody,
                    SourceType.IMPORTED
                );
            }
            if (function == null) {
                throw new IllegalStateException("could not create selected function at " + start);
            }
            selected.add(function);
        }
        selected.sort(Comparator.comparing(Function::getEntryPoint));
        println(
            "DIFFSEARCHVULN_SELECTION functions=" + selected.size() +
            " source=" + selectionPath
        );
        return selected;
    }

    private DecompInterface createDecompiler() {
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Ghidra decompiler could not open the imported program");
        }
        return decompiler;
    }

    private void validateArchitecture(String requestedArchitecture) {
        String language = currentProgram.getLanguageID().toString().toLowerCase();
        boolean requestedArm = requestedArchitecture.equals("arm64") ||
            requestedArchitecture.equals("arm64e");
        if (requestedArm && !language.startsWith("aarch64:")) {
            throw new IllegalStateException(
                "requested " + requestedArchitecture + " but Ghidra loaded language " + language +
                "; universal binaries must be thinned before analysis"
            );
        }
    }

    private ExportedFunction exportFunction(
            Function function,
            DecompInterface decompiler,
            int functionTimeoutSeconds,
            String artifactSha256,
            String architecture) throws Exception {
        List<String> warnings = new ArrayList<>();
        String decompilation = null;
        DecompileResults results = decompiler.decompileFunction(
            function,
            functionTimeoutSeconds,
            monitor
        );
        if (results != null && results.decompileCompleted() && results.getDecompiledFunction() != null) {
            decompilation = results.getDecompiledFunction().getC();
        }
        else {
            String message = results == null ? "no decompiler result" : results.getErrorMessage();
            warnings.add("decompilation_failed: " + safeText(message));
        }

        List<String> instructions = new ArrayList<>();
        Set<String> strings = new TreeSet<>();
        Set<String> imports = new TreeSet<>();
        InstructionIterator instructionIterator = currentProgram.getListing().getInstructions(
            function.getBody(),
            true
        );
        while (instructionIterator.hasNext()) {
            Instruction instruction = instructionIterator.next();
            instructions.add(instruction.getAddress() + "|" + instruction.toString());
            for (Reference reference : instruction.getReferencesFrom()) {
                Data data = currentProgram.getListing().getDataAt(reference.getToAddress());
                if (data == null) {
                    data = currentProgram.getListing().getDataContaining(reference.getToAddress());
                }
                if (data != null && data.hasStringValue() && data.getValue() != null) {
                    strings.add(data.getValue().toString());
                }
            }
        }

        List<String> callers = functionNames(function.getCallingFunctions(monitor));
        Set<Function> calledFunctions = function.getCalledFunctions(monitor);
        List<String> callees = functionNames(calledFunctions);
        for (Function called : calledFunctions) {
            if (called.isExternal() || called.isThunk()) {
                imports.add(functionKey(called));
            }
        }

        return new ExportedFunction(
            artifactSha256,
            architecture,
            Application.getApplicationVersion(),
            currentProgram.getName(),
            currentProgram.getLanguageID().toString(),
            currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString(),
            function,
            decompilation,
            instructions,
            callers,
            callees,
            strings,
            imports,
            warnings
        );
    }

    private List<String> functionNames(Collection<Function> functions) {
        List<Function> ordered = new ArrayList<>(functions);
        ordered.sort(Comparator.comparing(Function::getEntryPoint));
        List<String> names = new ArrayList<>();
        for (Function function : ordered) {
            names.add(functionKey(function));
        }
        return names;
    }

    private String functionKey(Function function) {
        Address entry = function.getEntryPoint();
        return function.getName(true) + "@" + (entry == null ? "external" : entry.toString());
    }

    private static String safeText(String value) {
        return value == null || value.isBlank() ? "unspecified" : value;
    }

    private static String jsonString(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder escaped = new StringBuilder(value.length() + 2);
        escaped.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"': escaped.append("\\\""); break;
                case '\\': escaped.append("\\\\"); break;
                case '\b': escaped.append("\\b"); break;
                case '\f': escaped.append("\\f"); break;
                case '\n': escaped.append("\\n"); break;
                case '\r': escaped.append("\\r"); break;
                case '\t': escaped.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) character));
                    }
                    else {
                        escaped.append(character);
                    }
            }
        }
        escaped.append('"');
        return escaped.toString();
    }

    private static String stringArray(Collection<String> values) {
        StringBuilder output = new StringBuilder("[");
        boolean first = true;
        for (String value : values) {
            if (!first) {
                output.append(',');
            }
            output.append(jsonString(value));
            first = false;
        }
        return output.append(']').toString();
    }

    private static class ExportedFunction {
        final String artifactSha256;
        final String architecture;
        final String ghidraVersion;
        final String programName;
        final String languageId;
        final String compilerSpecId;
        final Function function;
        final String decompilation;
        final List<String> instructions;
        final List<String> callers;
        final List<String> callees;
        final Set<String> strings;
        final Set<String> imports;
        final List<String> warnings;

        ExportedFunction(
                String artifactSha256,
                String architecture,
                String ghidraVersion,
                String programName,
                String languageId,
                String compilerSpecId,
                Function function,
                String decompilation,
                List<String> instructions,
                List<String> callers,
                List<String> callees,
                Set<String> strings,
                Set<String> imports,
                List<String> warnings) {
            this.artifactSha256 = artifactSha256;
            this.architecture = architecture;
            this.ghidraVersion = ghidraVersion;
            this.programName = programName;
            this.languageId = languageId;
            this.compilerSpecId = compilerSpecId;
            this.function = function;
            this.decompilation = decompilation;
            this.instructions = instructions;
            this.callers = callers;
            this.callees = callees;
            this.strings = strings;
            this.imports = imports;
            this.warnings = warnings;
        }

        String toJson() {
            StringBuilder json = new StringBuilder();
            json.append('{');
            json.append("\"schema_version\":").append(jsonString(SCHEMA_VERSION));
            json.append(",\"artifact_sha256\":").append(jsonString(artifactSha256));
            json.append(",\"architecture\":").append(jsonString(architecture));
            json.append(",\"ghidra_version\":").append(jsonString(ghidraVersion));
            json.append(",\"program_name\":").append(jsonString(programName));
            json.append(",\"language_id\":").append(jsonString(languageId));
            json.append(",\"compiler_spec_id\":").append(jsonString(compilerSpecId));
            json.append(",\"function\":{");
            json.append("\"address\":").append(jsonString(function.getEntryPoint().toString()));
            json.append(",\"name\":").append(jsonString(function.getName()));
            json.append(",\"qualified_name\":").append(jsonString(function.getName(true)));
            json.append(",\"namespace\":").append(jsonString(function.getParentNamespace().getName(true)));
            json.append(",\"body_size\":").append(function.getBody().getNumAddresses());
            json.append(",\"parameter_count\":").append(function.getParameterCount());
            json.append(",\"calling_convention\":").append(jsonString(function.getCallingConventionName()));
            json.append(",\"thunk\":").append(function.isThunk());
            json.append(",\"external\":").append(function.isExternal());
            json.append(",\"decompilation\":").append(jsonString(decompilation));
            json.append(",\"instructions\":").append(stringArray(instructions));
            json.append(",\"callers\":").append(stringArray(callers));
            json.append(",\"callees\":").append(stringArray(callees));
            json.append(",\"strings\":").append(stringArray(strings));
            json.append(",\"imports\":").append(stringArray(imports));
            json.append('}');
            json.append(",\"warnings\":").append(stringArray(warnings));
            json.append('}');
            return json.toString();
        }
    }
}
