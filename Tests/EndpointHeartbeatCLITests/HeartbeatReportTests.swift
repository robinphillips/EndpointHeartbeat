import Foundation
@testable import EndpointHeartbeatCLI
@testable import EndpointHeartbeatCore
import Testing

struct HeartbeatReportTests {
    @Test("reports render certificate validity and outcomes consistently")
    func writesMarkdownAndJSONReports() throws {
        let endpoint = Endpoint(
            name: "Example API",
            reportGroup: "Example",
            url: URL(string: "https://api.example.com/health")!,
            certificates: [
                .init(id: "active-root", role: .root, spkiSHA256Base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
                .init(
                    id: "expected-failure",
                    role: .root,
                    spkiSHA256Base64: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                    expectedOutcome: .trustFailure
                )
            ],
            acceptableStatusCodes: [200]
        )
        let certificate = ObservedCertificate(
            role: .leaf,
            spkiSHA256Base64: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
            notBefore: Date(timeIntervalSince1970: 0),
            notAfter: Date(timeIntervalSince1970: 3_600)
        )
        let results = [
            CheckResult(
                endpoint: endpoint,
                pin: endpoint.certificates[0],
                observedOutcome: .success(statusCode: 200),
                endpointCertificate: certificate
            ),
            CheckResult(
                endpoint: endpoint,
                pin: endpoint.certificates[1],
                observedOutcome: .trustFailure("no configured certificate pin matched: root SPKI SHA-256 was CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="),
                endpointCertificate: certificate
            ),
            CheckResult(
                endpoint: endpoint,
                pin: endpoint.certificates[0],
                observedOutcome: .httpFailure(statusCode: 503)
            ),
            CheckResult(
                endpoint: endpoint,
                pin: endpoint.certificates[0],
                observedOutcome: .transportFailure("offline")
            )
        ]
        let report = HeartbeatReport(results: results)
        let directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        let markdownURL = directory.appendingPathComponent("heartbeat-report-\(UUID().uuidString).md")
        let jsonURL = directory.appendingPathComponent("heartbeat-report-\(UUID().uuidString).json")
        defer {
            try? FileManager.default.removeItem(at: markdownURL)
            try? FileManager.default.removeItem(at: jsonURL)
        }

        try report.writeMarkdown(to: markdownURL)
        try report.writeJSON(to: jsonURL)

        let markdown = try String(contentsOf: markdownURL)
        let json = try String(contentsOf: jsonURL)
        #expect(markdown.contains("## Example"))
        #expect(markdown.contains("Endpoint: https://api.example.com/health"))
        #expect(markdown.contains("| --- | --- | --- | --- | --- |"))
        #expect(markdown.contains("Outcome: Success<br>HTTP status: 200<br>Endpoint leaf valid from: 1970-01-01T00:00:00Z<br>Endpoint leaf expires: 1970-01-01T01:00:00Z"))
        #expect(markdown.contains("Reason: No configured certificate pin matched<br>Observed root SPKI SHA-256 (Base64): `CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=`"))
        #expect(markdown.contains("Outcome: HTTP failure<br>HTTP status: 503"))
        #expect(markdown.contains("Outcome: Transport failure<br>offline"))
        #expect(json.contains("\"endpointCertificate\""))
        #expect(json.contains("\"notBefore\" : \"1970-01-01T00:00:00Z\""))
    }

    @Test("reports derive domain headings and status-code expectations")
    func writesDerivedDomainAndStatusRanges() throws {
        let endpoint = Endpoint(
            name: "API",
            url: URL(string: "https://api.example.com/health")!,
            certificates: [.init(id: "root", role: .root, spkiSHA256Base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")],
            acceptableStatusCodes: [200, 201, 202]
        )
        let report = HeartbeatReport(results: [
            .init(endpoint: endpoint, pin: endpoint.certificates[0], observedOutcome: .success(statusCode: 200))
        ])
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("heartbeat-report-\(UUID().uuidString).md")
        defer { try? FileManager.default.removeItem(at: url) }

        try report.writeMarkdown(to: url)

        let markdown = try String(contentsOf: url)
        #expect(markdown.contains("## example.com"))
        #expect(markdown.contains("| HTTP 200–202 |"))
    }

    @Test(arguments: [
        (CLIError.unknownCommand("run"), "unknown command: run"),
        (.missingConfig, "--config <file.json> is required"),
        (.invalidInspectURL, "inspect requires one HTTPS URL")
    ])
    func describesCLIError(error: CLIError, description: String) {
        #expect(error.description == description)
    }
}
