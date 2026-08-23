import Foundation
import Testing
@testable import DiffSearchVulnCore

@Test func jsonValuePreservesIntegerAndNestedValues() throws {
    let source = Data(#"{"count":54190,"ok":true,"items":["destPath",null]}"#.utf8)
    let decoded = try JSONDecoder().decode(JSONValue.self, from: source)
    #expect(
        decoded == .object([
            "count": .integer(54_190),
            "ok": .boolean(true),
            "items": .array([.string("destPath"), .null]),
        ])
    )
    let encoded = try JSONEncoder().encode(decoded)
    #expect(try JSONDecoder().decode(JSONValue.self, from: encoded) == decoded)
}

@Test func workerRequestUsesTheStrictWireKeys() throws {
    let encoded = try JSONEncoder().encode(
        WorkerRequest(id: "request", method: "system.hello", params: EmptyParameters())
    )
    let object = try #require(
        JSONSerialization.jsonObject(with: encoded) as? [String: Any]
    )
    #expect(Set(object.keys) == ["protocol_version", "id", "method", "params"])
    #expect(object["protocol_version"] as? String == diffSearchVulnProtocolVersion)
    let parameters = try #require(object["params"] as? [String: Any])
    #expect(parameters.isEmpty)
}

@Test func exploitAttemptCarriesTheLiveActivityIdentifier() throws {
    let context = WorkerExploitAnalysisContext(
        analysisTitle: "fixture",
        provenance: "local",
        sourceURL: "",
        selectedHypothesis: "path traversal",
        testInput: "../outside",
        expectedOutcome: "blocked",
        labNotes: ""
    )
    let encoded = try JSONEncoder().encode(
        ExploitAttemptParameters(
            runDirectory: "/tmp/run",
            attemptID: "ui-attempt-123",
            analysisContext: context
        )
    )
    let object = try #require(
        JSONSerialization.jsonObject(with: encoded) as? [String: Any]
    )
    #expect(object["run_directory"] as? String == "/tmp/run")
    #expect(object["attempt_id"] as? String == "ui-attempt-123")
    let wireContext = try #require(object["analysis_context"] as? [String: Any])
    #expect(wireContext["execution_mode"] as? String == "simulation")
    #expect(wireContext["vm_identifier"] as? String == "")
}

@Test func finalAnalysisDecodesSiblingImplementationSearch() throws {
    let source = Data(#"""
    {
        "finding_state":"likely_patch",
        "selected_candidate_ids":["candidate-a"],
        "confidence":0.94,
        "vulnerable_behavior":"unchecked path",
        "attacker_preconditions":["controlled path"],
        "security_invariant":"path remains below root",
        "patch_explanation":"new containment check",
        "observed_evidence":["new branch"],
        "inferences":["security intent"],
        "bypass_hypotheses":["alternate normalization"],
        "sibling_implementation_search":{
            "status":"partial",
            "searched_function_ids":["candidate-a"],
            "same_function_call_sites":[{
                "function":"example.routeRequest",
                "relationship":"direct caller",
                "evidence":"callee edge targets the patched validator",
                "risk":"uncertain",
                "next_test":"exercise the alternate route"
            }],
            "similar_implementations":[],
            "coverage_notes":["all functions scanned"],
            "unresolved_gaps":["one decompilation omitted"]
        }
    }
    """#.utf8)

    let analysis = try JSONDecoder().decode(WorkerFinalAnalysis.self, from: source)

    #expect(analysis.siblingImplementationSearch?.status == "partial")
    #expect(
        analysis.siblingImplementationSearch?.sameFunctionCallSites.first?.function
            == "example.routeRequest"
    )
    #expect(analysis.siblingImplementationSearch?.unresolvedGaps.count == 1)
}

@Test func realWorkerNegotiatesProtocolAndPersistsProducts() throws {
    let fileManager = FileManager.default
    let python = URL(fileURLWithPath: "/opt/homebrew/bin/python3.12")
    guard fileManager.isExecutableFile(atPath: python.path) else {
        return
    }
    let repositoryRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let client = WorkerClient(
        configuration: WorkerLaunchConfiguration(
            pythonExecutable: python,
            repositoryRoot: repositoryRoot
        )
    )
    try client.start()
    defer { client.stop() }

    let hello = try client.hello()
    #expect(hello.protocolVersion == diffSearchVulnProtocolVersion)
    #expect(hello.safetyMode == "static_by_default_explicit_contained_dynamic")

    let temporary = fileManager.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try fileManager.createDirectory(at: temporary, withIntermediateDirectories: true)
    defer { try? fileManager.removeItem(at: temporary) }
    let database = temporary.appendingPathComponent("state.sqlite3")
    let created = try client.createProduct(
        database: database,
        name: "Swift Client Fixture",
        vendor: "DiffSearchVuln"
    )
    #expect(created.product.name == "Swift Client Fixture")
    let listed = try client.listProducts(database: database)
    #expect(listed.count == 1)
    #expect(listed.products.first?.id == created.product.id)
}

@Test func realWorkerDecodesRcloneCandidatesAndEvidenceWhenFixtureExists() throws {
    let fileManager = FileManager.default
    let python = URL(fileURLWithPath: "/opt/homebrew/bin/python3.12")
    guard fileManager.isExecutableFile(atPath: python.path) else {
        return
    }
    let repositoryRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let diff = repositoryRoot
        .appendingPathComponent("ghidra-projects/rclone/diffs/completed")
        .appendingPathComponent(
            "39493e5381e1412bf6edc2e8e5938c0b5978fd0971ad753f714637aef518bb52"
        )
    guard fileManager.fileExists(atPath: diff.path) else {
        return
    }
    let client = WorkerClient(
        configuration: WorkerLaunchConfiguration(
            pythonExecutable: python,
            repositoryRoot: repositoryRoot
        )
    )
    try client.start()
    defer { client.stop() }

    let page = try client.listCandidates(diffDirectory: diff, limit: 2)
    #expect(page.totalCount == 54_190)
    #expect(page.candidates.first?.primaryName.hasSuffix("extract.destPath") == true)
    let candidate = try #require(page.candidates.first)
    let result = try client.candidateEvidence(
        diffDirectory: diff,
        candidateID: candidate.id
    )
    #expect(result.evidence.candidate.id == candidate.id)
    #expect(result.evidence.oldRecord == nil)
    #expect(result.evidence.newRecord?.function.decompilation?.isEmpty == false)

    let tournamentDirectory = repositoryRoot
        .appendingPathComponent("ghidra-projects/rclone/tournaments/runs")
        .appendingPathComponent(
            "bdcb16d95c51997c9be169b92ad841a9eb0bc3566bc625bbc6cc0e9e3d0d3a89"
        )
    if fileManager.fileExists(atPath: tournamentDirectory.path) {
        let tournament = try client.inspectTournament(runDirectory: tournamentDirectory)
        #expect(tournament.run.status == "completed")
        #expect(tournament.run.finalistIDs.count == 2)
        #expect(tournament.run.finalAnalysis?.confidence == 0.99)
        #expect(tournament.run.finalAnalysis?.findingState == "likely_patch")
        _ = try client.latestCodexExploitAttempt(
            runDirectory: tournamentDirectory
        )
    }
}
