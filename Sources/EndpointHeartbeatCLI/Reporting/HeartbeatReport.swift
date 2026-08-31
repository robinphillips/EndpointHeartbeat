import EndpointHeartbeatCore
import Foundation

struct HeartbeatReport: Encodable {
    let generatedAt: Date
    let passedChecks: Int
    let totalChecks: Int
    let checks: [HeartbeatReportCheck]

    init(results: [CheckResult]) {
        generatedAt = .now
        passedChecks = results.filter(\.passed).count
        totalChecks = results.count
        checks = results.map(HeartbeatReportCheck.init)
    }

    func writeJSON(to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: url, options: .atomic)
    }

    func writeMarkdown(to url: URL) throws {
        let formatter = ISO8601DateFormatter()
        var lines = [
            "# Endpoint heartbeat",
            "",
            "Generated: \(formatter.string(from: generatedAt))",
            "",
            "**\(passedChecks)/\(totalChecks) checks passed**",
            "",
            "| Status | Endpoint | Result | Expected |",
            "| --- | --- | --- | --- |"
        ]
        lines += checks.map { check in
            "| \(check.passed ? "✅" : "❌") | \(check.name) | \(check.displayResult) | \(check.displayExpectedOutcome) |"
        }
        try (lines.joined(separator: "\n") + "\n").write(to: url, atomically: true, encoding: .utf8)
    }
}

private extension HeartbeatReportCheck {
    var displayExpectedOutcome: String {
        switch expectedOutcome {
        case "success": displayExpectedHTTPStatus
        case "trustFailure": "trust failure"
        default: expectedOutcome
        }
    }

    var displayExpectedHTTPStatus: String {
        let statusCodes = acceptableStatusCodes.sorted()
        guard let first = statusCodes.first else { return "HTTP status" }
        guard statusCodes.count > 1 else { return "HTTP \(first)" }
        if statusCodes == Array(first...(first + statusCodes.count - 1)) {
            return "HTTP \(first)–\(statusCodes.last!)"
        }
        return "HTTP \(statusCodes.map(String.init).joined(separator: ", "))"
    }

    var displayResult: String {
        let pins = pins.map(displayPin).joined(separator: "<br><br>")
        let warnings = warnings.map { "⚠️ \($0)" }.joined(separator: "<br>")
        return ["Outcome: \(outcome)", displayOutcomeDetails, "URL: \(url.absoluteString)", "Configured pins:<br>\(pins)", warnings]
            .filter { !$0.isEmpty }
            .joined(separator: "<br>")
    }

    func displayPin(_ pin: HeartbeatReportPin) -> String {
        [
            "ID: `\(pin.id)`",
            "Role: `\(pin.role)`",
            "State: `\(pin.state)`",
            "SPKI SHA-256 (Base64): `\(pin.spkiSHA256Base64)`"
        ].joined(separator: "<br>")
    }

    var displayOutcomeDetails: String {
        let prefix = "no configured certificate pin matched: root SPKI SHA-256 was "
        guard outcome == "Trust failure", outcomeDetails.hasPrefix(prefix) else {
            return outcomeDetails
        }
        let hash = outcomeDetails.dropFirst(prefix.count)
        return "Reason: No configured certificate pin matched<br>Observed certificate:<br>Role: `root`<br>SPKI SHA-256 (Base64): `\(hash)`"
    }
}
