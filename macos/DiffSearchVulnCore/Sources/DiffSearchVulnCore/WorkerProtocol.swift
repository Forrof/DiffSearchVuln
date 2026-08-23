import Foundation

public let diffSearchVulnProtocolVersion = "1.0.0"

public enum JSONValue: Codable, Equatable, Sendable {
    case null
    case boolean(Bool)
    case integer(Int64)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .boolean(value)
        } else if let value = try? container.decode(Int64.self) {
            self = .integer(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unsupported JSON value"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null:
            try container.encodeNil()
        case .boolean(let value):
            try container.encode(value)
        case .integer(let value):
            try container.encode(value)
        case .number(let value):
            try container.encode(value)
        case .string(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .object(let value):
            try container.encode(value)
        }
    }
}

public struct WorkerHello: Decodable, Equatable, Sendable {
    public let workerVersion: String
    public let protocolVersion: String
    public let capabilities: [String]
    public let safetyMode: String

    enum CodingKeys: String, CodingKey {
        case workerVersion = "worker_version"
        case protocolVersion = "protocol_version"
        case capabilities
        case safetyMode = "safety_mode"
    }
}

public struct WorkerProduct: Decodable, Equatable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let vendor: String?
    public let createdAt: String

    enum CodingKeys: String, CodingKey {
        case id, name, vendor
        case createdAt = "created_at"
    }
}

public struct WorkerProductList: Decodable, Equatable, Sendable {
    public let products: [WorkerProduct]
    public let count: Int
}

public struct WorkerCreatedProduct: Decodable, Equatable, Sendable {
    public let product: WorkerProduct
}

public struct WorkerStoreInitialization: Decodable, Equatable, Sendable {
    public let database: String
    public let schemaVersion: Int

    enum CodingKeys: String, CodingKey {
        case database
        case schemaVersion = "schema_version"
    }
}

public struct WorkerCandidatePage: Decodable, Equatable, Sendable {
    public let diffCacheKey: String
    public let offset: Int
    public let limit: Int
    public let totalCount: Int
    public let candidates: [WorkerCandidate]

    enum CodingKeys: String, CodingKey {
        case diffCacheKey = "diff_cache_key"
        case offset, limit
        case totalCount = "total_count"
        case candidates
    }
}

public struct WorkerCandidate: Decodable, Equatable, Identifiable, Sendable {
    public let candidateID: String
    public let primaryName: String
    public let matchKind: String
    public let matchConfidence: Double?
    public let deterministicScore: Double
    public let deterministicRank: Int
    public let inTournamentPool: Bool
    public let oldFunction: WorkerFunctionReference?
    public let newFunction: WorkerFunctionReference?
    public let changeEvidence: WorkerChangeEvidence
    public let clusterMembers: [WorkerClusterMember]

    public var id: String { candidateID }

    enum CodingKeys: String, CodingKey {
        case candidateID = "candidate_id"
        case primaryName = "primary_name"
        case matchKind = "match_kind"
        case matchConfidence = "match_confidence"
        case deterministicScore = "deterministic_score"
        case deterministicRank = "deterministic_rank"
        case inTournamentPool = "in_tournament_pool"
        case oldFunction = "old_function"
        case newFunction = "new_function"
        case changeEvidence = "change_evidence"
        case clusterMembers = "cluster_members"
    }
}

public struct WorkerFunctionReference: Decodable, Equatable, Sendable {
    public let address: String
    public let name: String
    public let rawName: String?
    public let nameSource: String?
    public let bodySize: Int
    public let instructionCount: Int
    public let branchCount: Int
    public let compareCount: Int
    public let callCount: Int
    public let callerCount: Int
    public let calleeCount: Int
    public let warningCount: Int

    enum CodingKeys: String, CodingKey {
        case address, name
        case rawName = "raw_name"
        case nameSource = "name_source"
        case bodySize = "body_size"
        case instructionCount = "instruction_count"
        case branchCount = "branch_count"
        case compareCount = "compare_count"
        case callCount = "call_count"
        case callerCount = "caller_count"
        case calleeCount = "callee_count"
        case warningCount = "warning_count"
    }
}

public struct WorkerChangeEvidence: Decodable, Equatable, Sendable {
    public let advisoryTermsMatched: [String]
    public let bodySizeDelta: Int
    public let instructionCountDelta: Int
    public let branchCountDelta: Int
    public let compareCountDelta: Int
    public let stringsAdded: [String]
    public let stringsRemoved: [String]
    public let importsAdded: [String]
    public let importsRemoved: [String]
    public let noiseSignals: [String]

    enum CodingKeys: String, CodingKey {
        case advisoryTermsMatched = "advisory_terms_matched"
        case bodySizeDelta = "body_size_delta"
        case instructionCountDelta = "instruction_count_delta"
        case branchCountDelta = "branch_count_delta"
        case compareCountDelta = "compare_count_delta"
        case stringsAdded = "strings_added"
        case stringsRemoved = "strings_removed"
        case importsAdded = "imports_added"
        case importsRemoved = "imports_removed"
        case noiseSignals = "noise_signals"
    }
}

public struct WorkerClusterMember: Decodable, Equatable, Identifiable, Sendable {
    public let candidateID: String
    public let name: String
    public let kind: String

    public var id: String { candidateID }

    enum CodingKeys: String, CodingKey {
        case candidateID = "candidate_id"
        case name, kind
    }
}

public struct WorkerCandidateEvidence: Decodable, Equatable, Sendable {
    public let evidence: WorkerEvidenceDossier
}

public struct WorkerTournamentInspection: Decodable, Equatable, Sendable {
    public let run: WorkerTournamentRun
}

public struct WorkerTournamentRun: Decodable, Equatable, Sendable {
    public let runKey: String
    public let runPath: String
    public let status: String
    public let diffCacheKey: String
    public let model: String
    public let poolCount: Int
    public let groupCount: Int
    public let codexCallCount: Int
    public let reusedDecisionCount: Int
    public let finalistIDs: [String]
    public let passFinalists: [String]
    public let startedAt: String?
    public let completedAt: String?
    public let finalAnalysis: WorkerFinalAnalysis?

    enum CodingKeys: String, CodingKey {
        case runKey = "run_key"
        case runPath = "run_path"
        case status
        case diffCacheKey = "diff_cache_key"
        case model
        case poolCount = "pool_count"
        case groupCount = "group_count"
        case codexCallCount = "codex_call_count"
        case reusedDecisionCount = "reused_decision_count"
        case finalistIDs = "finalist_ids"
        case passFinalists = "pass_finalists"
        case startedAt = "started_at"
        case completedAt = "completed_at"
        case finalAnalysis = "final_analysis"
    }
}

public struct WorkerFinalAnalysis: Decodable, Equatable, Sendable {
    public let findingState: String
    public let selectedCandidateIDs: [String]
    public let confidence: Double
    public let vulnerableBehavior: String
    public let attackerPreconditions: [String]
    public let securityInvariant: String
    public let patchExplanation: String
    public let observedEvidence: [String]
    public let inferences: [String]
    public let bypassHypotheses: [String]
    public let siblingImplementationSearch: WorkerSiblingImplementationSearch?

    enum CodingKeys: String, CodingKey {
        case findingState = "finding_state"
        case selectedCandidateIDs = "selected_candidate_ids"
        case confidence
        case vulnerableBehavior = "vulnerable_behavior"
        case attackerPreconditions = "attacker_preconditions"
        case securityInvariant = "security_invariant"
        case patchExplanation = "patch_explanation"
        case observedEvidence = "observed_evidence"
        case inferences
        case bypassHypotheses = "bypass_hypotheses"
        case siblingImplementationSearch = "sibling_implementation_search"
    }
}

public struct WorkerSiblingImplementationSearch: Decodable, Equatable, Sendable {
    public let status: String
    public let searchedFunctionIDs: [String]
    public let sameFunctionCallSites: [WorkerSiblingImplementationFinding]
    public let similarImplementations: [WorkerSiblingImplementationFinding]
    public let coverageNotes: [String]
    public let unresolvedGaps: [String]

    enum CodingKeys: String, CodingKey {
        case status
        case searchedFunctionIDs = "searched_function_ids"
        case sameFunctionCallSites = "same_function_call_sites"
        case similarImplementations = "similar_implementations"
        case coverageNotes = "coverage_notes"
        case unresolvedGaps = "unresolved_gaps"
    }
}

public struct WorkerSiblingImplementationFinding: Decodable, Equatable, Sendable, Identifiable {
    public let function: String
    public let relationship: String
    public let evidence: String
    public let risk: String
    public let nextTest: String

    public var id: String { "\(function):\(relationship)" }

    enum CodingKeys: String, CodingKey {
        case function, relationship, evidence, risk
        case nextTest = "next_test"
    }
}

public struct WorkerExploitAttemptResponse: Decodable, Equatable, Sendable {
    public let attempt: WorkerCodexExploitAttempt?
}

public struct WorkerCodexExploitAttempt: Decodable, Equatable, Sendable {
    public let attemptID: String
    public let attemptDirectory: String
    public let createdAt: String
    public let model: String
    public let threadID: String
    public let turnID: String
    public let durationMilliseconds: Int?
    public let tokenUsage: JSONValue?
    public let promptSHA256: String
    public let mode: String?
    public let generatedFiles: [String]
    public let result: WorkerExploitResult

    enum CodingKeys: String, CodingKey {
        case attemptID = "attempt_id"
        case attemptDirectory = "attempt_directory"
        case createdAt = "created_at"
        case model
        case threadID = "thread_id"
        case turnID = "turn_id"
        case durationMilliseconds = "duration_ms"
        case tokenUsage = "token_usage"
        case promptSHA256 = "prompt_sha256"
        case mode
        case generatedFiles = "generated_files"
        case result
    }
}

public struct WorkerExploitResult: Decodable, Equatable, Sendable {
    public let verdict: String
    public let summary: String
    public let attemptedHypothesis: String
    public let exploitChain: [String]
    public let testCases: [WorkerExploitTestCase]
    public let bypassCandidates: [WorkerExploitBypassCandidate]
    public let artifacts: [WorkerExploitArtifact]
    public let limitations: [String]
    public let nextAction: String

    enum CodingKeys: String, CodingKey {
        case verdict, summary
        case attemptedHypothesis = "attempted_hypothesis"
        case exploitChain = "exploit_chain"
        case testCases = "test_cases"
        case bypassCandidates = "bypass_candidates"
        case artifacts, limitations
        case nextAction = "next_action"
    }
}

public struct WorkerExploitTestCase: Decodable, Equatable, Sendable, Identifiable {
    public let name: String
    public let setup: String
    public let testInputs: [String]
    public let steps: [String]
    public let expectedVulnerableResult: String
    public let expectedPatchedResult: String
    public let observedResult: String
    public let status: String

    public var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name, setup, steps, status
        case testInputs = "test_inputs"
        case expectedVulnerableResult = "expected_vulnerable_result"
        case expectedPatchedResult = "expected_patched_result"
        case observedResult = "observed_result"
    }
}

public struct WorkerExploitBypassCandidate: Decodable, Equatable, Sendable, Identifiable {
    public let hypothesis: String
    public let likelihood: String
    public let reasoning: String
    public let nextTest: String

    public var id: String { hypothesis }

    enum CodingKeys: String, CodingKey {
        case hypothesis, likelihood, reasoning
        case nextTest = "next_test"
    }
}

public struct WorkerExploitArtifact: Decodable, Equatable, Sendable, Identifiable {
    public let path: String
    public let purpose: String

    public var id: String { path }
}

public struct WorkerEvidenceDossier: Decodable, Equatable, Sendable {
    public let candidate: WorkerCandidate
    public let oldRecord: WorkerFunctionRecord?
    public let newRecord: WorkerFunctionRecord?
    public let related: [WorkerRelatedEvidence]

    enum CodingKeys: String, CodingKey {
        case candidate, related
        case oldRecord = "old_record"
        case newRecord = "new_record"
    }
}

public struct WorkerRelatedEvidence: Decodable, Equatable, Sendable {
    public let candidate: WorkerCandidate
    public let oldRecord: WorkerFunctionRecord?
    public let newRecord: WorkerFunctionRecord?

    enum CodingKeys: String, CodingKey {
        case candidate
        case oldRecord = "old_record"
        case newRecord = "new_record"
    }
}

public struct WorkerFunctionRecord: Decodable, Equatable, Sendable {
    public let artifactSHA256: String
    public let architecture: String
    public let ghidraVersion: String
    public let languageID: String
    public let compilerSpecID: String
    public let function: WorkerFunctionEvidence
    public let warnings: [String]

    enum CodingKeys: String, CodingKey {
        case artifactSHA256 = "artifact_sha256"
        case architecture
        case ghidraVersion = "ghidra_version"
        case languageID = "language_id"
        case compilerSpecID = "compiler_spec_id"
        case function, warnings
    }
}

public struct WorkerFunctionEvidence: Decodable, Equatable, Sendable {
    public let address: String
    public let name: String
    public let qualifiedName: String
    public let bodySize: Int
    public let parameterCount: Int
    public let decompilation: String?
    public let instructions: [String]
    public let callers: [String]
    public let callees: [String]
    public let strings: [String]
    public let imports: [String]

    enum CodingKeys: String, CodingKey {
        case address, name
        case qualifiedName = "qualified_name"
        case bodySize = "body_size"
        case parameterCount = "parameter_count"
        case decompilation, instructions, callers, callees, strings, imports
    }
}

public struct WorkerRemoteError: Decodable, Error, Equatable, LocalizedError, Sendable {
    public let code: String
    public let message: String
    public let data: JSONValue?

    public var errorDescription: String? { message }
}

public enum WorkerClientError: Error, Equatable, LocalizedError, Sendable {
    case alreadyRunning
    case notRunning
    case launchFailed(String)
    case workerExited(status: Int32, detail: String?)
    case responseTooLarge
    case unexpectedEndOfStream
    case invalidResponse(String)
    case protocolMismatch(expected: String, actual: String)
    case responseIDMismatch(expected: String, actual: String?)

    public var errorDescription: String? {
        switch self {
        case .alreadyRunning:
            return "The worker is already running."
        case .notRunning:
            return "The worker is not running."
        case .launchFailed(let detail):
            return "The worker could not be launched: \(detail)"
        case .workerExited(let status, let detail):
            if let detail, !detail.isEmpty {
                return "The worker exited with status \(status): \(detail)"
            }
            return "The worker exited with status \(status)."
        case .responseTooLarge:
            return "The worker response exceeded the client limit."
        case .unexpectedEndOfStream:
            return "The worker closed its response stream unexpectedly."
        case .invalidResponse(let detail):
            return "The worker returned an invalid response: \(detail)"
        case .protocolMismatch(let expected, let actual):
            return "Worker protocol mismatch; expected \(expected), received \(actual)."
        case .responseIDMismatch(let expected, let actual):
            return "Worker response ID mismatch; expected \(expected), received \(actual ?? "null")."
        }
    }
}

struct WorkerRequest<Parameters: Encodable>: Encodable {
    let protocolVersion = diffSearchVulnProtocolVersion
    let id: String
    let method: String
    let params: Parameters

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case id, method, params
    }
}

struct WorkerResponse<Result: Decodable>: Decodable {
    let protocolVersion: String
    let id: String?
    let result: Result?
    let error: WorkerRemoteError?

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case id, result, error
    }
}

struct EmptyParameters: Encodable {}

struct DoctorParameters: Encodable {
    let deep: Bool
}

struct DatabaseParameters: Encodable {
    let database: String
}

struct CreateProductParameters: Encodable {
    let database: String
    let name: String
    let vendor: String?
}

struct CandidatePageParameters: Encodable {
    let diffDirectory: String
    let offset: Int
    let limit: Int

    enum CodingKeys: String, CodingKey {
        case diffDirectory = "diff_directory"
        case offset, limit
    }
}

struct CandidateEvidenceParameters: Encodable {
    let diffDirectory: String
    let candidateID: String
    let includeRelated: Int
    let includeInstructions: Bool

    enum CodingKeys: String, CodingKey {
        case diffDirectory = "diff_directory"
        case candidateID = "candidate_id"
        case includeRelated = "include_related"
        case includeInstructions = "include_instructions"
    }
}

struct TournamentInspectionParameters: Encodable {
    let runDirectory: String

    enum CodingKeys: String, CodingKey {
        case runDirectory = "run_directory"
    }
}

public struct WorkerExploitAnalysisContext: Encodable, Equatable, Sendable {
    public let analysisTitle: String
    public let provenance: String
    public let sourceURL: String
    public let selectedHypothesis: String
    public let testInput: String
    public let expectedOutcome: String
    public let labNotes: String
    public let executionMode: String
    public let vmIdentifier: String

    public init(
        analysisTitle: String,
        provenance: String,
        sourceURL: String,
        selectedHypothesis: String,
        testInput: String,
        expectedOutcome: String,
        labNotes: String,
        executionMode: String = "simulation",
        vmIdentifier: String = ""
    ) {
        self.analysisTitle = analysisTitle
        self.provenance = provenance
        self.sourceURL = sourceURL
        self.selectedHypothesis = selectedHypothesis
        self.testInput = testInput
        self.expectedOutcome = expectedOutcome
        self.labNotes = labNotes
        self.executionMode = executionMode
        self.vmIdentifier = vmIdentifier
    }

    enum CodingKeys: String, CodingKey {
        case analysisTitle = "analysis_title"
        case provenance
        case sourceURL = "source_url"
        case selectedHypothesis = "selected_hypothesis"
        case testInput = "test_input"
        case expectedOutcome = "expected_outcome"
        case labNotes = "lab_notes"
        case executionMode = "execution_mode"
        case vmIdentifier = "vm_identifier"
    }
}

struct ExploitAttemptParameters: Encodable {
    let runDirectory: String
    let attemptID: String
    let analysisContext: WorkerExploitAnalysisContext

    enum CodingKeys: String, CodingKey {
        case runDirectory = "run_directory"
        case attemptID = "attempt_id"
        case analysisContext = "analysis_context"
    }
}
