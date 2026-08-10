import Foundation

public struct WorkerLaunchConfiguration: Sendable {
    public let pythonExecutable: URL
    public let repositoryRoot: URL
    public let additionalEnvironment: [String: String]

    public init(
        pythonExecutable: URL,
        repositoryRoot: URL,
        additionalEnvironment: [String: String] = [:]
    ) {
        self.pythonExecutable = pythonExecutable
        self.repositoryRoot = repositoryRoot
        self.additionalEnvironment = additionalEnvironment
    }
}

public final class WorkerClient {
    public static let maximumResponseBytes = 67_108_864

    private let configuration: WorkerLaunchConfiguration
    private let lock = NSLock()
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private var process: Process?
    private var requestInput: FileHandle?
    private var responseOutput: FileHandle?
    private var errorOutput: FileHandle?
    private var responseBuffer = Data()

    public init(configuration: WorkerLaunchConfiguration) {
        self.configuration = configuration
    }

    deinit {
        stop()
    }

    public var isRunning: Bool {
        lock.withLock { process?.isRunning == true }
    }

    public func start() throws {
        try lock.withLock {
            if process?.isRunning == true {
                throw WorkerClientError.alreadyRunning
            }
            let requestPipe = Pipe()
            let responsePipe = Pipe()
            let errorPipe = Pipe()
            let launchedProcess = Process()
            launchedProcess.executableURL = configuration.pythonExecutable
            launchedProcess.arguments = ["-m", "diffsearchvuln", "worker"]
            launchedProcess.currentDirectoryURL = configuration.repositoryRoot
            launchedProcess.standardInput = requestPipe
            launchedProcess.standardOutput = responsePipe
            launchedProcess.standardError = errorPipe

            var environment = ProcessInfo.processInfo.environment
            for (key, value) in configuration.additionalEnvironment {
                environment[key] = value
            }
            let sourcePath = configuration.repositoryRoot.appendingPathComponent("src").path
            if let existing = environment["PYTHONPATH"], !existing.isEmpty {
                environment["PYTHONPATH"] = sourcePath + ":" + existing
            } else {
                environment["PYTHONPATH"] = sourcePath
            }
            launchedProcess.environment = environment
            do {
                try launchedProcess.run()
            } catch {
                throw WorkerClientError.launchFailed(error.localizedDescription)
            }
            try? requestPipe.fileHandleForReading.close()
            try? responsePipe.fileHandleForWriting.close()
            try? errorPipe.fileHandleForWriting.close()
            process = launchedProcess
            requestInput = requestPipe.fileHandleForWriting
            responseOutput = responsePipe.fileHandleForReading
            errorOutput = errorPipe.fileHandleForReading
            responseBuffer.removeAll(keepingCapacity: true)
        }
    }

    public func stop() {
        lock.withLock {
            try? requestInput?.close()
            requestInput = nil
            responseOutput = nil
            errorOutput = nil
            responseBuffer.removeAll(keepingCapacity: false)
            if let process, process.isRunning {
                process.terminate()
            }
            process = nil
        }
    }

    public func hello() throws -> WorkerHello {
        try send(method: "system.hello", parameters: EmptyParameters(), as: WorkerHello.self)
    }

    public func doctor(deep: Bool = false) throws -> JSONValue {
        try send(method: "system.doctor", parameters: DoctorParameters(deep: deep), as: JSONValue.self)
    }

    public func listProducts(database: URL) throws -> WorkerProductList {
        try send(
            method: "products.list",
            parameters: DatabaseParameters(database: database.path),
            as: WorkerProductList.self
        )
    }

    public func initializeStore(database: URL) throws -> WorkerStoreInitialization {
        try send(
            method: "store.initialize",
            parameters: DatabaseParameters(database: database.path),
            as: WorkerStoreInitialization.self
        )
    }

    public func createProduct(
        database: URL,
        name: String,
        vendor: String? = nil
    ) throws -> WorkerCreatedProduct {
        try send(
            method: "products.create",
            parameters: CreateProductParameters(
                database: database.path,
                name: name,
                vendor: vendor
            ),
            as: WorkerCreatedProduct.self
        )
    }

    public func listCandidates(
        diffDirectory: URL,
        offset: Int = 0,
        limit: Int = 50
    ) throws -> WorkerCandidatePage {
        try send(
            method: "candidates.list",
            parameters: CandidatePageParameters(
                diffDirectory: diffDirectory.path,
                offset: offset,
                limit: limit
            ),
            as: WorkerCandidatePage.self
        )
    }

    public func candidateEvidence(
        diffDirectory: URL,
        candidateID: String,
        includeRelated: Int = 0,
        includeInstructions: Bool = false
    ) throws -> WorkerCandidateEvidence {
        try send(
            method: "candidate.evidence",
            parameters: CandidateEvidenceParameters(
                diffDirectory: diffDirectory.path,
                candidateID: candidateID,
                includeRelated: includeRelated,
                includeInstructions: includeInstructions
            ),
            as: WorkerCandidateEvidence.self
        )
    }

    public func inspectTournament(runDirectory: URL) throws -> WorkerTournamentInspection {
        try send(
            method: "tournament.inspect",
            parameters: TournamentInspectionParameters(runDirectory: runDirectory.path),
            as: WorkerTournamentInspection.self
        )
    }

    public func runCodexExploitAttempt(
        runDirectory: URL,
        attemptID: String,
        context: WorkerExploitAnalysisContext
    ) throws -> WorkerExploitAttemptResponse {
        try send(
            method: "exploit.codex_attempt",
            parameters: ExploitAttemptParameters(
                runDirectory: runDirectory.path,
                attemptID: attemptID,
                analysisContext: context
            ),
            as: WorkerExploitAttemptResponse.self
        )
    }

    public func latestCodexExploitAttempt(
        runDirectory: URL
    ) throws -> WorkerExploitAttemptResponse {
        try send(
            method: "exploit.latest",
            parameters: TournamentInspectionParameters(
                runDirectory: runDirectory.path
            ),
            as: WorkerExploitAttemptResponse.self
        )
    }

    private func send<Parameters: Encodable, Result: Decodable>(
        method: String,
        parameters: Parameters,
        as resultType: Result.Type
    ) throws -> Result {
        try lock.withLock {
            guard let process, process.isRunning,
                  let requestInput,
                  responseOutput != nil else {
                if let process, !process.isRunning {
                    throw WorkerClientError.workerExited(
                        status: process.terminationStatus,
                        detail: readErrorOutput()
                    )
                }
                throw WorkerClientError.notRunning
            }
            let requestID = UUID().uuidString.lowercased()
            var requestData = try encoder.encode(
                WorkerRequest(
                    id: requestID,
                    method: method,
                    params: parameters
                )
            )
            requestData.append(0x0A)
            requestInput.write(requestData)
            let responseData = try readResponseLine()
            let response: WorkerResponse<Result>
            do {
                response = try decoder.decode(WorkerResponse<Result>.self, from: responseData)
            } catch {
                throw WorkerClientError.invalidResponse(error.localizedDescription)
            }
            guard response.protocolVersion == diffSearchVulnProtocolVersion else {
                throw WorkerClientError.protocolMismatch(
                    expected: diffSearchVulnProtocolVersion,
                    actual: response.protocolVersion
                )
            }
            guard response.id == requestID else {
                throw WorkerClientError.responseIDMismatch(
                    expected: requestID,
                    actual: response.id
                )
            }
            if let error = response.error {
                throw error
            }
            guard let result = response.result else {
                throw WorkerClientError.invalidResponse("missing result and error")
            }
            return result
        }
    }

    private func readResponseLine() throws -> Data {
        while true {
            if let newline = responseBuffer.firstIndex(of: 0x0A) {
                let line = responseBuffer[..<newline]
                responseBuffer.removeSubrange(...newline)
                return Data(line)
            }
            guard responseBuffer.count <= Self.maximumResponseBytes else {
                throw WorkerClientError.responseTooLarge
            }
            guard let responseOutput else {
                throw WorkerClientError.notRunning
            }
            let chunk = responseOutput.availableData
            guard !chunk.isEmpty else {
                if let process {
                    process.waitUntilExit()
                    throw WorkerClientError.workerExited(
                        status: process.terminationStatus,
                        detail: readErrorOutput()
                    )
                }
                throw WorkerClientError.unexpectedEndOfStream
            }
            responseBuffer.append(chunk)
        }
    }

    private func readErrorOutput() -> String? {
        guard let errorOutput else { return nil }
        let data = errorOutput.readDataToEndOfFile()
        guard !data.isEmpty else { return nil }
        return String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
