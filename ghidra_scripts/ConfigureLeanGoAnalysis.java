// Keep code/function recovery while avoiding DWARF's very large type graph on
// Go binaries that otherwise exhaust the headless JVM before dossier export.
// @category DiffSearchVuln

import ghidra.app.script.GhidraScript;

public class ConfigureLeanGoAnalysis extends GhidraScript {
    @Override
    protected void run() throws Exception {
        setAnalysisOption(currentProgram, "DWARF", "false");
        println("DIFFSEARCHVULN_ANALYSIS_PROFILE dwarf=false");
    }
}
