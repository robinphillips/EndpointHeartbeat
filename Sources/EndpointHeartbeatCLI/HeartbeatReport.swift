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
            "| Status | Endpoint | Observed | Expected |",
            "| --- | --- | --- | --- |"
        ]
        lines += checks.map { check in
            "| \(check.passed ? "✅" : "❌") | \(check.name) | \(check.observedOutcome) | \(check.expectedOutcome) |"
        }
        for check in checks where !check.warnings.isEmpty {
            lines.append("")
            lines.append("## Warnings: \(check.name)")
            lines += check.warnings.map { "- ⚠️ \($0)" }
        }
        try (lines.joined(separator: "\n") + "\n").write(to: url, atomically: true, encoding: .utf8)
    }
}
