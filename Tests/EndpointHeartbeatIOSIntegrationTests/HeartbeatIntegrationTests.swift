import Foundation
@testable import EndpointHeartbeatCore
import XCTest

final class HeartbeatIntegrationTests: XCTestCase {
    func testConfiguredEndpointsMatchTheirExpectedOutcomes() async throws {
        guard let configurationURL = Bundle.module.url(forResource: "heartbeat", withExtension: "json") else {
            throw XCTSkip("Missing heartbeat configuration")
        }

        let configuration = try ConfigurationLoader.load(from: configurationURL)
        let results = await Heartbeat.checkAll(configuration.endpoints)
        let title = ProcessInfo.processInfo.environment["REPORT_TITLE"] ?? "Endpoint heartbeat"
        let configurationName = ProcessInfo.processInfo.environment["CONFIG_NAME"] ?? "heartbeat.json"
        let report = HeartbeatReport(results: results, title: title, configurationName: configurationName)
        let timestamp = reportTimestamp(report.generatedAt)
        addReportAttachment(
            data: try report.jsonData(),
            name: "heartbeat-report-\(timestamp).json",
            uniformTypeIdentifier: "public.json"
        )
        addReportAttachment(
            data: Data(report.markdown().utf8),
            name: "heartbeat-report-\(timestamp).md",
            uniformTypeIdentifier: "net.daringfireball.markdown"
        )

        for result in results where !result.passed {
            XCTFail(
                "\(result.endpoint.name) [\(result.checkID)] observed \(result.observedOutcome.description); expected \(result.expectedOutcome.rawValue)"
            )
        }
    }

    private func reportTimestamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        return formatter.string(from: date)
    }

    private func addReportAttachment(data: Data, name: String, uniformTypeIdentifier: String) {
        let attachment = XCTAttachment(data: data, uniformTypeIdentifier: uniformTypeIdentifier)
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
