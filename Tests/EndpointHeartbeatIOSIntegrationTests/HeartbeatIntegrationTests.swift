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
        let report = HeartbeatReport(results: results)
        addReportAttachment(
            data: try report.jsonData(),
            name: "heartbeat-report.json",
            uniformTypeIdentifier: "public.json"
        )
        addReportAttachment(
            data: Data(report.markdown().utf8),
            name: "heartbeat-report.md",
            uniformTypeIdentifier: "net.daringfireball.markdown"
        )

        for result in results where !result.passed {
            XCTFail(
                "\(result.endpoint.name) [\(result.pin.id)] observed \(result.observedOutcome.description); expected \(result.pin.expectedOutcome.rawValue)"
            )
        }
    }

    private func addReportAttachment(data: Data, name: String, uniformTypeIdentifier: String) {
        let attachment = XCTAttachment(data: data, uniformTypeIdentifier: uniformTypeIdentifier)
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
