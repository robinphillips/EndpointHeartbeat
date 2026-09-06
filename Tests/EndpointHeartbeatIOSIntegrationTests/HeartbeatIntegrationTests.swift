import Foundation
@testable import EndpointHeartbeatCore
import Testing

struct HeartbeatIntegrationTests {
    @Test("configured endpoints match their expected outcomes on iOS")
    func checksConfiguredEndpoints() async throws {
        guard let configurationURL = Bundle.module.url(forResource: "heartbeat", withExtension: "json") else {
            return
        }

        let configuration = try ConfigurationLoader.load(from: configurationURL)
        let results = await Heartbeat.checkAll(configuration.endpoints)
        let report = HeartbeatReport(results: results)
        try Attachment.record(String(decoding: report.jsonData(), as: UTF8.self), named: "heartbeat-report.json")
        Attachment.record(report.markdown(), named: "heartbeat-report.md")

        for result in results where !result.passed {
            Issue.record(
                "\(result.endpoint.name) [\(result.pin.id)] observed \(result.observedOutcome.description); expected \(result.pin.expectedOutcome.rawValue)"
            )
        }
    }
}
