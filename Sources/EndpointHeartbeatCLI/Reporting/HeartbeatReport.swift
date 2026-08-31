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
        ]
        var groups: [(host: String, checks: [HeartbeatReportCheck])] = []
        for check in checks {
            let host = check.url.host ?? check.url.absoluteString
            if let index = groups.firstIndex(where: { $0.host == host }) {
                groups[index].checks.append(check)
            } else {
                groups.append((host: host, checks: [check]))
            }
        }
        for group in groups {
            let endpoints = Array(Set(group.checks.map { $0.url.absoluteString })).sorted()
            lines += [
                "",
                "## \(displayDomain(for: group.host))",
                "",
                "Endpoint: \(endpoints.joined(separator: ", "))",
                "",
                "| Status | Check | Pin | Result | Expected |",
                "| --- | --- | --- | --- |"
            ]
            lines += group.checks.enumerated().sorted { lhs, rhs in
                lhs.element.displayOrder == rhs.element.displayOrder
                    ? lhs.offset < rhs.offset
                    : lhs.element.displayOrder < rhs.element.displayOrder
            }.map {
                "| \($0.element.passed ? "✅" : "❌") | \($0.element.displayCheckName) | \($0.element.displayPin) | \($0.element.displayResult) | \($0.element.displayExpectedOutcome) |"
            }
        }
        try (lines.joined(separator: "\n") + "\n").write(to: url, atomically: true, encoding: .utf8)
    }

    private func displayDomain(for host: String) -> String {
        let labels = host.split(separator: ".")
        guard labels.count > 2 else { return host }
        return labels.suffix(2).joined(separator: ".")
    }
}

private extension HeartbeatReportCheck {
    var displayOrder: Int {
        guard passed else { return 0 }
        return expectedOutcome == "trustFailure" ? 2 : 1
    }

    var displayCheckName: String {
        expectedOutcome == "trustFailure" && !name.hasSuffix(" - expected failure")
            ? "\(name) - expected failure"
            : name
    }

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
        let warnings = warnings.map { "⚠️ \($0)" }.joined(separator: " · ")
        return ["Outcome: \(outcome)", displayOutcomeDetails, warnings]
            .filter { !$0.isEmpty }
            .joined(separator: " · ")
    }

    var displayPin: String {
        return [
            "ID `\(pin.id)`",
            "Role `\(pin.role)`",
            "State `\(pin.state)`",
            "SPKI SHA-256 (Base64) `\(pin.spkiSHA256Base64)`"
        ].joined(separator: " · ")
    }

    var displayOutcomeDetails: String {
        let prefix = "no configured certificate pin matched: root SPKI SHA-256 was "
        guard outcome == "Trust failure", outcomeDetails.hasPrefix(prefix) else {
            return outcomeDetails
        }
        let hash = outcomeDetails.dropFirst(prefix.count)
        return "Reason: No configured certificate pin matched · Observed root SPKI SHA-256 (Base64) `\(hash)`"
    }
}
