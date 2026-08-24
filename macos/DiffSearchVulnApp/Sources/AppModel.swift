import DiffSearchVulnCore
import Foundation
import Observation

enum AppSection: String, CaseIterable, Identifiable {
    case analyses
    case products
    case programs
    case settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .analyses: "Analyses"
        case .products: "Products"
        case .programs: "Program Intelligence"
        case .settings: "Settings"
        }
    }

    var icon: String {
        switch self {
        case .analyses: "square.stack.3d.up"
        case .products: "shippingbox"
        case .programs: "checkmark.shield"
        case .settings: "gearshape"
        }
    }
}

enum BountyProgramAccess: String, Codable, CaseIterable, Identifiable {
    case publicProgram = "Public program"
    case privateInvite = "Private invite"

    var id: String { rawValue }
}

enum BountyProgramLifecycle: String, Codable, CaseIterable, Identifiable {
    case active = "Active"
    case paused = "Paused"
    case closed = "Closed"
    case applicationOnly = "Application portal only"
    case notReviewed = "Not reviewed"

    var id: String { rawValue }
}

enum BountyToolingPolicy: String, Codable, CaseIterable, Identifiable {
    case explicitlyAllowed = "Patch analysis explicitly allowed"
    case scannersProhibited = "Scanners prohibited; manual analysis allowed"
    case clarificationRequired = "Written clarification required"
    case prohibited = "Diff tooling prohibited"
    case notReviewed = "Not reviewed"

    var id: String { rawValue }
}

enum BountyDisclosurePolicy: String, Codable, CaseIterable, Identifiable {
    case coordinated = "Coordinated disclosure"
    case permanentNondisclosure = "Permanent nondisclosure"
    case privateProgram = "Private-program terms"
    case notReviewed = "Not reviewed"

    var id: String { rawValue }
}

enum ProgramGateStatus: String {
    case eligible = "Eligible"
    case reviewRequired = "Review required"
    case blocked = "Blocked"
    case excluded = "Excluded"
}

struct BountyProgramRecord: Codable, Hashable, Identifiable {
    let id: String
    var name: String
    var platform: String
    var programURL: String
    var targetName: String
    var maximumP1Reward: String
    var maximumP2Reward: String
    var access: BountyProgramAccess
    var lifecycle: BountyProgramLifecycle
    var toolingPolicy: BountyToolingPolicy
    var disclosurePolicy: BountyDisclosurePolicy
    var isPaid: Bool
    var highCriticalInScope: Bool
    var localTestingAllowed: Bool
    var adjacentReleasesAvailable: Bool
    var scopeReviewed: Bool
    var scopeReviewedAt: Date
    var identityVerified: Bool
    var priorReportConflict: Bool
    var notes: String

    var gateStatus: ProgramGateStatus {
        if lifecycle == .paused || lifecycle == .closed || lifecycle == .applicationOnly {
            return .excluded
        }
        if priorReportConflict || !isPaid || !localTestingAllowed || toolingPolicy == .prohibited {
            return .excluded
        }
        if !identityVerified {
            return .blocked
        }
        if lifecycle != .active || !highCriticalInScope || !adjacentReleasesAvailable
            || !scopeReviewed || toolingPolicy == .notReviewed
            || toolingPolicy == .clarificationRequired || disclosurePolicy == .notReviewed {
            return .reviewRequired
        }
        let sevenDaysAgo = Calendar.current.date(byAdding: .day, value: -7, to: Date()) ?? Date()
        if scopeReviewedAt < sevenDaysAgo {
            return .reviewRequired
        }
        return .eligible
    }

    var gateExplanation: String {
        if lifecycle == .paused { return "Testing is paused. Do not analyze or submit until the brief reopens." }
        if lifecycle == .closed { return "The program is closed." }
        if lifecycle == .applicationOnly { return "This page accepts applications, not vulnerability reports." }
        if priorReportConflict { return "A prior or active report conflicts with the program-selection rule." }
        if !isPaid { return "The current campaign is limited to paid bounty programs." }
        if !localTestingAllowed { return "The target cannot be validated entirely in an authorized local environment." }
        if toolingPolicy == .prohibited { return "The program rules prohibit the required diff tooling." }
        if !identityVerified { return "Identity verification must be completed before Bugcrowd will accept a report." }
        if lifecycle != .active { return "Confirm that the program is active before testing." }
        if !highCriticalInScope { return "Confirm that High/Critical product vulnerabilities are reward-eligible." }
        if !adjacentReleasesAvailable { return "Obtain an official adjacent release pair before starting patch analysis." }
        if !scopeReviewed { return "Read the complete current brief, targets, exclusions, and disclosure terms." }
        if toolingPolicy == .notReviewed { return "Classify the program's tooling and scanner policy." }
        if toolingPolicy == .clarificationRequired { return "Obtain written clarification before using DiffSearchVuln." }
        if disclosurePolicy == .notReviewed { return "Record the disclosure and confidentiality requirements." }
        let sevenDaysAgo = Calendar.current.date(byAdding: .day, value: -7, to: Date()) ?? Date()
        if scopeReviewedAt < sevenDaysAgo { return "The saved scope review is stale; reread the brief before testing." }
        return "The program passes the selection gates. Recheck its brief again immediately before submission."
    }
}

enum AnalysisTab: String, CaseIterable, Identifiable {
    case summary
    case diff
    case tournament
    case findings
    case exploitLab

    var id: String { rawValue }

    var title: String {
        switch self {
        case .summary: "Summary"
        case .diff: "Function Diff"
        case .tournament: "Tournament"
        case .findings: "Findings"
        case .exploitLab: "Exploit Lab"
        }
    }

    var icon: String {
        switch self {
        case .summary: "doc.text"
        case .diff: "arrow.left.arrow.right"
        case .tournament: "arrow.triangle.branch"
        case .findings: "shield.lefthalf.filled"
        case .exploitLab: "flask"
        }
    }
}

enum LabAttemptResult: String, Codable, CaseIterable, Identifiable {
    case notRun = "Not run"
    case blocked = "Blocked"
    case bypassed = "Bypassed"
    case inconclusive = "Inconclusive"

    var id: String { rawValue }
}

struct ExploitLabAttempt: Codable, Hashable, Identifiable {
    let id: String
    let createdAt: Date
    var hypothesis: String
    var testInput: String
    var expectedOutcome: String
    var observation: String
    var result: LabAttemptResult
}

struct CodexActivitySession: Identifiable, Equatable {
    let id: String
    let attemptDirectory: URL
    let startedAt: Date
    let executionMode: String

    var isDynamic: Bool { executionMode != "simulation" }
    var isHostDynamic: Bool { executionMode == "host_dynamic" }
}

struct AnalysisCase: Codable, Hashable, Identifiable {
    let id: String
    var title: String
    var productName: String
    var oldVersion: String
    var newVersion: String
    var binaryDescription: String
    var sourceDescription: String
    var sourceURL: String
    var diffDirectory: String?
    var tournamentRunDirectory: String?
    var labAttempts: [ExploitLabAttempt]?

    var provenanceSentence: String {
        "\(binaryDescription) was compared from version \(oldVersion) to \(newVersion) using releases obtained from \(sourceDescription)."
    }
}

private struct RepositoryAnalysisCaseManifest: Decodable {
    let schemaVersion: String
    let id: String
    let title: String
    let productName: String
    let oldVersion: String
    let newVersion: String
    let binaryDescription: String
    let sourceDescription: String
    let sourceURL: String
    let diffDirectory: String
    let tournamentRunDirectory: String

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case id
        case title
        case productName = "product_name"
        case oldVersion = "old_version"
        case newVersion = "new_version"
        case binaryDescription = "binary_description"
        case sourceDescription = "source_description"
        case sourceURL = "source_url"
        case diffDirectory = "diff_directory"
        case tournamentRunDirectory = "tournament_run_directory"
    }
}

enum WorkerConnectionState: Equatable {
    case disconnected
    case connecting
    case connected(version: String)
    case failed(String)

    var label: String {
        switch self {
        case .disconnected: "Disconnected"
        case .connecting: "Connecting…"
        case .connected(let version): "Worker \(version)"
        case .failed: "Connection failed"
        }
    }
}

actor WorkerBridge {
    private let client: WorkerClient

    init(configuration: WorkerLaunchConfiguration) {
        client = WorkerClient(configuration: configuration)
    }

    func connect(database: URL) throws -> (WorkerHello, WorkerStoreInitialization, WorkerProductList) {
        try client.start()
        let hello = try client.hello()
        let store = try client.initializeStore(database: database)
        let products = try client.listProducts(database: database)
        return (hello, store, products)
    }

    func stop() {
        client.stop()
    }

    func listProducts(database: URL) throws -> WorkerProductList {
        try client.listProducts(database: database)
    }

    func createProduct(database: URL, name: String, vendor: String?) throws -> WorkerCreatedProduct {
        try client.createProduct(database: database, name: name, vendor: vendor)
    }

    func listCandidates(directory: URL, offset: Int, limit: Int) throws -> WorkerCandidatePage {
        try client.listCandidates(diffDirectory: directory, offset: offset, limit: limit)
    }

    func evidence(directory: URL, candidateID: String) throws -> WorkerCandidateEvidence {
        try client.candidateEvidence(
            diffDirectory: directory,
            candidateID: candidateID,
            includeRelated: 2,
            includeInstructions: false
        )
    }

    func inspectTournament(directory: URL) throws -> WorkerTournamentInspection {
        try client.inspectTournament(runDirectory: directory)
    }

    func runCodexExploit(
        directory: URL,
        attemptID: String,
        context: WorkerExploitAnalysisContext
    ) throws -> WorkerExploitAttemptResponse {
        try client.runCodexExploitAttempt(
            runDirectory: directory,
            attemptID: attemptID,
            context: context
        )
    }

    func latestCodexExploit(directory: URL) throws -> WorkerExploitAttemptResponse {
        try client.latestCodexExploitAttempt(runDirectory: directory)
    }
}

@MainActor
@Observable
final class AppModel {
    var selection: AppSection = .analyses
    var analysisTab: AnalysisTab = .summary
    var analysisCases: [AnalysisCase] = []
    var selectedAnalysisID: String?
    var connectionState: WorkerConnectionState = .disconnected
    var products: [WorkerProduct] = []
    var bountyPrograms: [BountyProgramRecord] = []
    var selectedBountyProgramID: String?
    var candidatePage: WorkerCandidatePage?
    var selectedCandidateID: String?
    var selectedEvidence: WorkerEvidenceDossier?
    var tournamentRun: WorkerTournamentRun?
    var codexExploitAttempt: WorkerCodexExploitAttempt?
    var codexActivitySession: CodexActivitySession?
    var isLoadingProducts = false
    var isLoadingCandidates = false
    var isLoadingEvidence = false
    var isLoadingTournament = false
    var isRunningCodexExploit = false
    var presentedError: String?
    var storeSchemaVersion: Int?

    var repositoryRoot: String
    var pythonExecutable: String
    var databasePath: String
    var vaultRoot: String
    var analysisRoot: String
    var diffDirectory: String?
    var tournamentRunDirectory: String?

    @ObservationIgnored private let defaults = UserDefaults.standard
    @ObservationIgnored private var worker: WorkerBridge?
    @ObservationIgnored private var candidateLoadToken = UUID()
    @ObservationIgnored private var evidenceLoadToken = UUID()
    @ObservationIgnored private var tournamentLoadToken = UUID()
    @ObservationIgnored private var codexExploitLoadToken = UUID()

    init() {
        let applicationSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!.appendingPathComponent("DiffSearchVuln", isDirectory: true)
        let environmentRoot = ProcessInfo.processInfo.environment[
            "DIFFSEARCHVULN_REPOSITORY_ROOT"
        ]
        let bundledDevelopmentRoot = Bundle.main.object(
            forInfoDictionaryKey: "DSVRepositoryRoot"
        ) as? String
        let sourceDevelopmentRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .path
        repositoryRoot = UserDefaults.standard.string(forKey: "repositoryRoot")
            ?? environmentRoot
            ?? bundledDevelopmentRoot
            ?? sourceDevelopmentRoot
        pythonExecutable = UserDefaults.standard.string(forKey: "pythonExecutable")
            ?? "/opt/homebrew/bin/python3.12"
        databasePath = UserDefaults.standard.string(forKey: "databasePath")
            ?? applicationSupport.appendingPathComponent("state.sqlite3").path
        vaultRoot = UserDefaults.standard.string(forKey: "vaultRoot")
            ?? applicationSupport.appendingPathComponent("Vault", isDirectory: true).path
        analysisRoot = UserDefaults.standard.string(forKey: "analysisRoot")
            ?? applicationSupport.appendingPathComponent("Analysis", isDirectory: true).path
        diffDirectory = nil
        let defaultTournament = URL(fileURLWithPath: repositoryRoot)
            .appendingPathComponent("ghidra-projects/rclone/tournaments/runs")
            .appendingPathComponent(
                "bdcb16d95c51997c9be169b92ad841a9eb0bc3566bc625bbc6cc0e9e3d0d3a89"
            )
        tournamentRunDirectory = nil

        if let encoded = defaults.data(forKey: "bountyPrograms"),
           let decoded = try? JSONDecoder().decode([BountyProgramRecord].self, from: encoded) {
            bountyPrograms = decoded
        }
        let storedProgramSelection = defaults.string(forKey: "selectedBountyProgramID")
        selectedBountyProgramID = bountyPrograms.contains { $0.id == storedProgramSelection }
            ? storedProgramSelection : bountyPrograms.first?.id

        if let encoded = defaults.data(forKey: "analysisCases"),
           let decoded = try? JSONDecoder().decode([AnalysisCase].self, from: encoded) {
            analysisCases = decoded
        } else {
            let fixtureDiff = acceptanceFixtureURL.path
            let storedDiff = defaults.string(forKey: "diffDirectory")
            let storedTournament = defaults.string(forKey: "tournamentRunDirectory")
            let resolvedDiff = storedDiff
                ?? (FileManager.default.fileExists(atPath: fixtureDiff) ? fixtureDiff : nil)
            let resolvedTournament = storedTournament
                ?? (FileManager.default.fileExists(atPath: defaultTournament.path)
                    ? defaultTournament.path : nil)
            if resolvedDiff != nil || resolvedTournament != nil {
                analysisCases = [AnalysisCase(
                    id: "rclone-1.74.3-1.74.4",
                    title: "rclone 1.74.3 → 1.74.4",
                    productName: "rclone",
                    oldVersion: "1.74.3",
                    newVersion: "1.74.4",
                    binaryDescription: "The rclone macOS Apple Silicon Mach-O binary",
                    sourceDescription: "the official downloads.rclone.org release archives",
                    sourceURL: "https://downloads.rclone.org",
                    diffDirectory: resolvedDiff,
                    tournamentRunDirectory: resolvedTournament,
                    labAttempts: []
                )]
            } else {
                analysisCases = []
            }
            persistAnalysisCases()
        }
        synchronizeRepositoryAnalysisCases()
        let storedSelection = defaults.string(forKey: "selectedAnalysisID")
        selectedAnalysisID = analysisCases.contains { $0.id == storedSelection }
            ? storedSelection : analysisCases.first?.id
        applySelectedAnalysisPaths()
        if ProcessInfo.processInfo.arguments.contains("--show-candidates") {
            analysisTab = .diff
        } else if ProcessInfo.processInfo.arguments.contains("--show-findings") {
            analysisTab = .findings
        } else if ProcessInfo.processInfo.arguments.contains("--show-tournament") {
            analysisTab = .tournament
        } else if ProcessInfo.processInfo.arguments.contains("--show-exploit-lab") {
            analysisTab = .exploitLab
        }
    }

    var databaseURL: URL { URL(fileURLWithPath: databasePath) }
    var diffDirectoryURL: URL? { diffDirectory.map(URL.init(fileURLWithPath:)) }
    var tournamentRunURL: URL? {
        tournamentRunDirectory.map(URL.init(fileURLWithPath:))
    }

    var selectedAnalysis: AnalysisCase? {
        analysisCases.first { $0.id == selectedAnalysisID }
    }

    var acceptanceFixtureURL: URL {
        URL(fileURLWithPath: repositoryRoot)
            .appendingPathComponent("ghidra-projects/rclone/diffs/completed")
            .appendingPathComponent(
                "39493e5381e1412bf6edc2e8e5938c0b5978fd0971ad753f714637aef518bb52"
            )
    }

    var acceptanceFixtureAvailable: Bool {
        FileManager.default.fileExists(atPath: acceptanceFixtureURL.path)
    }

    func connectIfNeeded() {
        guard case .disconnected = connectionState else { return }
        connect()
    }

    func connect() {
        connectionState = .connecting
        let oldWorker = worker
        let configuration = WorkerLaunchConfiguration(
            pythonExecutable: URL(fileURLWithPath: pythonExecutable),
            repositoryRoot: URL(fileURLWithPath: repositoryRoot)
        )
        let newWorker = WorkerBridge(configuration: configuration)
        worker = newWorker
        Task {
            await oldWorker?.stop()
            do {
                let (hello, store, productList) = try await newWorker.connect(
                    database: databaseURL
                )
                guard worker === newWorker else { return }
                connectionState = .connected(version: hello.workerVersion)
                storeSchemaVersion = store.schemaVersion
                products = productList.products
                loadSelectedAnalysis()
            } catch {
                guard worker === newWorker else { return }
                connectionState = .failed(error.localizedDescription)
                presentedError = error.localizedDescription
            }
        }
    }

    func refreshCurrentSection() {
        switch selection {
        case .products:
            refreshProducts()
        case .analyses:
            switch analysisTab {
            case .diff:
                if let directory = diffDirectoryURL {
                    loadCandidates(directory: directory, offset: candidatePage?.offset ?? 0)
                }
            case .tournament, .findings:
                if let directory = tournamentRunURL {
                    loadTournament(directory: directory)
                }
            case .summary, .exploitLab:
                loadSelectedAnalysis()
            }
        case .programs:
            break
        case .settings:
            connect()
        }
    }

    func addBountyProgram(name: String, programURL: String, targetName: String) {
        let record = BountyProgramRecord(
            id: UUID().uuidString,
            name: name,
            platform: "Bugcrowd",
            programURL: programURL,
            targetName: targetName,
            maximumP1Reward: "",
            maximumP2Reward: "",
            access: .publicProgram,
            lifecycle: .notReviewed,
            toolingPolicy: .notReviewed,
            disclosurePolicy: .notReviewed,
            isPaid: true,
            highCriticalInScope: false,
            localTestingAllowed: false,
            adjacentReleasesAvailable: false,
            scopeReviewed: false,
            scopeReviewedAt: Date(),
            identityVerified: false,
            priorReportConflict: false,
            notes: ""
        )
        bountyPrograms.append(record)
        selectedBountyProgramID = record.id
        defaults.set(record.id, forKey: "selectedBountyProgramID")
        persistBountyPrograms()
    }

    func replaceBountyProgram(_ record: BountyProgramRecord) {
        guard let index = bountyPrograms.firstIndex(where: { $0.id == record.id }) else {
            return
        }
        bountyPrograms[index] = record
        persistBountyPrograms()
    }

    func selectBountyProgram(_ identifier: String?) {
        selectedBountyProgramID = identifier
        defaults.set(identifier, forKey: "selectedBountyProgramID")
    }

    func removeSelectedBountyProgram() {
        guard let identifier = selectedBountyProgramID,
              let index = bountyPrograms.firstIndex(where: { $0.id == identifier }) else {
            return
        }
        bountyPrograms.remove(at: index)
        selectedBountyProgramID = bountyPrograms.first?.id
        defaults.set(selectedBountyProgramID, forKey: "selectedBountyProgramID")
        persistBountyPrograms()
    }

    func refreshProducts() {
        guard let worker else { return }
        isLoadingProducts = true
        Task {
            defer { isLoadingProducts = false }
            do {
                products = try await worker.listProducts(database: databaseURL).products
            } catch {
                presentedError = error.localizedDescription
            }
        }
    }

    func createProduct(name: String, vendor: String?) async -> Bool {
        guard let worker else { return false }
        do {
            _ = try await worker.createProduct(
                database: databaseURL,
                name: name,
                vendor: vendor
            )
            products = try await worker.listProducts(database: databaseURL).products
            return true
        } catch {
            presentedError = error.localizedDescription
            return false
        }
    }

    func useAcceptanceFixture() {
        selection = .analyses
        analysisTab = .diff
        if let fixture = analysisCases.first(where: { $0.id == "rclone-1.74.3-1.74.4" }) {
            selectAnalysis(fixture.id)
        }
        loadCandidates(directory: acceptanceFixtureURL, offset: 0)
    }

    func loadCandidates(directory: URL, offset: Int = 0) {
        guard let worker else {
            presentedError = "The analysis worker is not connected."
            return
        }
        diffDirectory = directory.path
        updateSelectedAnalysis { $0.diffDirectory = directory.path }
        let loadToken = UUID()
        candidateLoadToken = loadToken
        isLoadingCandidates = true
        selectedCandidateID = nil
        selectedEvidence = nil
        evidenceLoadToken = UUID()
        isLoadingEvidence = false
        Task {
            defer {
                if candidateLoadToken == loadToken {
                    isLoadingCandidates = false
                }
            }
            do {
                let page = try await worker.listCandidates(
                    directory: directory,
                    offset: max(0, offset),
                    limit: 50
                )
                guard candidateLoadToken == loadToken,
                      diffDirectory == directory.path else { return }
                candidatePage = page
                if let first = page.candidates.first {
                    selectCandidate(first)
                }
            } catch {
                guard candidateLoadToken == loadToken else { return }
                presentedError = error.localizedDescription
            }
        }
    }

    func selectCandidate(_ candidate: WorkerCandidate?) {
        guard let candidate, let directory = diffDirectoryURL, let worker else {
            selectedCandidateID = nil
            selectedEvidence = nil
            return
        }
        selectedCandidateID = candidate.id
        selectedEvidence = nil
        let loadToken = UUID()
        evidenceLoadToken = loadToken
        isLoadingEvidence = true
        Task {
            defer {
                if evidenceLoadToken == loadToken {
                    isLoadingEvidence = false
                }
            }
            do {
                let result = try await worker.evidence(
                    directory: directory,
                    candidateID: candidate.candidateID
                )
                guard evidenceLoadToken == loadToken,
                      selectedCandidateID == candidate.id,
                      diffDirectory == directory.path else { return }
                selectedEvidence = result.evidence
            } catch {
                guard evidenceLoadToken == loadToken else { return }
                presentedError = error.localizedDescription
            }
        }
    }

    func loadTournament(directory: URL) {
        guard let worker else {
            presentedError = "The analysis worker is not connected."
            return
        }
        tournamentRunDirectory = directory.path
        updateSelectedAnalysis { $0.tournamentRunDirectory = directory.path }
        let loadToken = UUID()
        tournamentLoadToken = loadToken
        isLoadingTournament = true
        Task {
            defer {
                if tournamentLoadToken == loadToken {
                    isLoadingTournament = false
                }
            }
            do {
                let run = try await worker.inspectTournament(
                    directory: directory
                ).run
                guard tournamentLoadToken == loadToken,
                      tournamentRunDirectory == directory.path else { return }
                tournamentRun = run
                loadLatestCodexExploit(directory: directory)
            } catch {
                guard tournamentLoadToken == loadToken else { return }
                presentedError = error.localizedDescription
            }
        }
    }

    func candidateName(for identifier: String) -> String {
        candidatePage?.candidates.first { $0.id == identifier }?.primaryName
            ?? String(identifier.prefix(16)) + "…"
    }

    func selectAnalysis(_ identifier: String?) {
        guard selectedAnalysisID != identifier else { return }
        selectedAnalysisID = identifier
        defaults.set(identifier, forKey: "selectedAnalysisID")
        applySelectedAnalysisPaths()
        candidatePage = nil
        selectedCandidateID = nil
        selectedEvidence = nil
        tournamentRun = nil
        codexExploitAttempt = nil
        codexActivitySession = nil
        candidateLoadToken = UUID()
        evidenceLoadToken = UUID()
        tournamentLoadToken = UUID()
        codexExploitLoadToken = UUID()
        isLoadingCandidates = false
        isLoadingEvidence = false
        isLoadingTournament = false
        isRunningCodexExploit = false
        loadSelectedAnalysis()
    }

    func addAnalysis(
        title: String,
        productName: String,
        oldVersion: String,
        newVersion: String,
        binaryDescription: String,
        sourceDescription: String,
        sourceURL: String,
        diffDirectory: String?,
        tournamentRunDirectory: String?
    ) {
        let analysis = AnalysisCase(
            id: UUID().uuidString,
            title: title,
            productName: productName,
            oldVersion: oldVersion,
            newVersion: newVersion,
            binaryDescription: binaryDescription,
            sourceDescription: sourceDescription,
            sourceURL: sourceURL,
            diffDirectory: normalizedOptionalPath(diffDirectory),
            tournamentRunDirectory: normalizedOptionalPath(tournamentRunDirectory),
            labAttempts: []
        )
        analysisCases.append(analysis)
        persistAnalysisCases()
        selectAnalysis(analysis.id)
        analysisTab = .summary
    }

    func recordLabAttempt(
        hypothesis: String,
        testInput: String,
        expectedOutcome: String,
        observation: String,
        result: LabAttemptResult
    ) {
        let attempt = ExploitLabAttempt(
            id: UUID().uuidString,
            createdAt: Date(),
            hypothesis: hypothesis,
            testInput: testInput,
            expectedOutcome: expectedOutcome,
            observation: observation,
            result: result
        )
        updateSelectedAnalysis {
            if $0.labAttempts == nil { $0.labAttempts = [] }
            $0.labAttempts?.insert(attempt, at: 0)
        }
    }

    func askCodexToExploit(
        selectedHypothesis: String,
        testInput: String,
        expectedOutcome: String,
        labNotes: String,
        executionMode: String = "simulation",
        vmIdentifier: String = ""
    ) {
        guard let worker,
              let directory = tournamentRunURL,
              let analysis = selectedAnalysis else {
            presentedError = "A selected analysis with a completed tournament is required."
            return
        }
        let analysisID = analysis.id
        let loadToken = UUID()
        let attemptID = UUID().uuidString.lowercased()
        let attemptDirectory = directory
            .appendingPathComponent("exploit-lab", isDirectory: true)
            .appendingPathComponent("codex-attempts", isDirectory: true)
            .appendingPathComponent(attemptID, isDirectory: true)
        codexExploitLoadToken = loadToken
        isRunningCodexExploit = true
        codexActivitySession = CodexActivitySession(
            id: attemptID,
            attemptDirectory: attemptDirectory,
            startedAt: Date(),
            executionMode: executionMode
        )
        let context = WorkerExploitAnalysisContext(
            analysisTitle: analysis.title,
            provenance: analysis.provenanceSentence,
            sourceURL: analysis.sourceURL,
            selectedHypothesis: selectedHypothesis,
            testInput: testInput,
            expectedOutcome: expectedOutcome,
            labNotes: labNotes,
            executionMode: executionMode,
            vmIdentifier: vmIdentifier
        )
        Task {
            defer {
                if codexExploitLoadToken == loadToken {
                    isRunningCodexExploit = false
                }
            }
            do {
                let response = try await worker.runCodexExploit(
                    directory: directory,
                    attemptID: attemptID,
                    context: context
                )
                guard codexExploitLoadToken == loadToken,
                      selectedAnalysisID == analysisID,
                      tournamentRunDirectory == directory.path else { return }
                codexExploitAttempt = response.attempt
            } catch {
                guard codexExploitLoadToken == loadToken else { return }
                presentedError = error.localizedDescription
            }
        }
    }

    private func normalizedOptionalPath(_ path: String?) -> String? {
        guard let path else { return nil }
        let value = path.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }

    private func loadSelectedAnalysis() {
        guard case .connected = connectionState else { return }
        if let directory = diffDirectoryURL {
            loadCandidates(directory: directory, offset: 0)
        }
        if let directory = tournamentRunURL {
            loadTournament(directory: directory)
        }
    }

    private func loadLatestCodexExploit(directory: URL) {
        guard let worker else { return }
        let analysisID = selectedAnalysisID
        let loadToken = UUID()
        codexExploitLoadToken = loadToken
        Task {
            do {
                let response = try await worker.latestCodexExploit(directory: directory)
                guard codexExploitLoadToken == loadToken,
                      selectedAnalysisID == analysisID,
                      tournamentRunDirectory == directory.path else { return }
                codexExploitAttempt = response.attempt
                if let attempt = response.attempt {
                    let formatter = ISO8601DateFormatter()
                    formatter.formatOptions = [
                        .withInternetDateTime,
                        .withFractionalSeconds,
                    ]
                    codexActivitySession = CodexActivitySession(
                        id: attempt.attemptID,
                        attemptDirectory: URL(fileURLWithPath: attempt.attemptDirectory),
                        startedAt: formatter.date(from: attempt.createdAt) ?? Date(),
                        executionMode: attempt.mode ?? "simulation"
                    )
                }
            } catch {
                guard codexExploitLoadToken == loadToken else { return }
                presentedError = error.localizedDescription
            }
        }
    }

    private func applySelectedAnalysisPaths() {
        diffDirectory = selectedAnalysis?.diffDirectory
        tournamentRunDirectory = selectedAnalysis?.tournamentRunDirectory
    }

    private func updateSelectedAnalysis(_ update: (inout AnalysisCase) -> Void) {
        guard let identifier = selectedAnalysisID,
              let index = analysisCases.firstIndex(where: { $0.id == identifier }) else {
            return
        }
        update(&analysisCases[index])
        persistAnalysisCases()
    }

    private func persistAnalysisCases() {
        if let encoded = try? JSONEncoder().encode(analysisCases) {
            defaults.set(encoded, forKey: "analysisCases")
        }
    }

    private func persistBountyPrograms() {
        if let encoded = try? JSONEncoder().encode(bountyPrograms) {
            defaults.set(encoded, forKey: "bountyPrograms")
        }
    }

    private func synchronizeRepositoryAnalysisCases() {
        let repositoryURL = URL(fileURLWithPath: repositoryRoot, isDirectory: true)
            .standardizedFileURL
        let casesURL = repositoryURL
            .appendingPathComponent("research/cases", isDirectory: true)
        guard let caseDirectories = try? FileManager.default.contentsOfDirectory(
            at: casesURL,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        ) else { return }

        let decoder = JSONDecoder()
        var changed = false
        for directory in caseDirectories.sorted(by: { $0.path < $1.path }) {
            let manifestURL = directory.appendingPathComponent("app-analysis.json")
            guard let data = try? Data(contentsOf: manifestURL),
                  let manifest = try? decoder.decode(
                    RepositoryAnalysisCaseManifest.self,
                    from: data
                  ),
                  manifest.schemaVersion == "1.0.0",
                  let diffPath = repositoryAnalysisPath(
                    manifest.diffDirectory,
                    repositoryURL: repositoryURL
                  ),
                  let tournamentPath = repositoryAnalysisPath(
                    manifest.tournamentRunDirectory,
                    repositoryURL: repositoryURL
                  ) else { continue }

            let existingAttempts = analysisCases.first(where: { $0.id == manifest.id })?
                .labAttempts ?? []
            let discovered = AnalysisCase(
                id: manifest.id,
                title: manifest.title,
                productName: manifest.productName,
                oldVersion: manifest.oldVersion,
                newVersion: manifest.newVersion,
                binaryDescription: manifest.binaryDescription,
                sourceDescription: manifest.sourceDescription,
                sourceURL: manifest.sourceURL,
                diffDirectory: diffPath,
                tournamentRunDirectory: tournamentPath,
                labAttempts: existingAttempts
            )
            if let index = analysisCases.firstIndex(where: { $0.id == manifest.id }) {
                if analysisCases[index] != discovered {
                    analysisCases[index] = discovered
                    changed = true
                }
            } else {
                analysisCases.append(discovered)
                changed = true
            }
        }
        if changed { persistAnalysisCases() }
    }

    private func repositoryAnalysisPath(
        _ relativePath: String,
        repositoryURL: URL
    ) -> String? {
        guard !relativePath.isEmpty,
              !relativePath.hasPrefix("/") else { return nil }
        let resolved = repositoryURL
            .appendingPathComponent(relativePath)
            .standardizedFileURL
        let rootPath = repositoryURL.path.hasSuffix("/")
            ? repositoryURL.path : repositoryURL.path + "/"
        guard resolved.path.hasPrefix(rootPath),
              FileManager.default.fileExists(atPath: resolved.path) else { return nil }
        return resolved.path
    }

    func saveSettings(
        repositoryRoot: String,
        pythonExecutable: String,
        databasePath: String,
        vaultRoot: String,
        analysisRoot: String
    ) {
        self.repositoryRoot = repositoryRoot
        self.pythonExecutable = pythonExecutable
        self.databasePath = databasePath
        self.vaultRoot = vaultRoot
        self.analysisRoot = analysisRoot
        defaults.set(repositoryRoot, forKey: "repositoryRoot")
        defaults.set(pythonExecutable, forKey: "pythonExecutable")
        defaults.set(databasePath, forKey: "databasePath")
        defaults.set(vaultRoot, forKey: "vaultRoot")
        defaults.set(analysisRoot, forKey: "analysisRoot")
        connectionState = .disconnected
        connect()
    }
}
