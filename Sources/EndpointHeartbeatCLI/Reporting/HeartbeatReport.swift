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
            "| \(check.passed ? "✅" : "❌") | \(check.name) | \(check.observedOutcome) | \(check.displayExpectedOutcome) |"
        }
        for check in checks {
            lines.append("")
            lines.append("<details>")
            lines.append("<summary>Details: \(check.name)</summary>")
            lines.append("")
            lines.append("- URL: \(check.url.absoluteString)")
            lines.append("- Configured pins:")
            lines += check.pins.map { pin in
                "  - \(pin.id) (\(pin.role), \(pin.state)): `\(pin.sha256)`"
            }
            if !check.warnings.isEmpty {
                lines.append("- Warnings:")
                lines += check.warnings.map { "  - ⚠️ \($0)" }
            }
            lines.append("")
            lines.append("</details>")
        }
        try (lines.joined(separator: "\n") + "\n").write(to: url, atomically: true, encoding: .utf8)
    }
}

private extension HeartbeatReportCheck {
    var displayExpectedOutcome: String {
        switch expectedOutcome {
        case "success": "success"
        case "trustFailure": "trust failure"
        default: expectedOutcome
        }
    }
}
