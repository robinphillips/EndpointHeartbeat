import Foundation

public enum CertificateInspector {
    public static func inspect(_ url: URL) async throws -> [CertificateInfo] {
        let delegate = InspectionDelegate()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 30
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        _ = try await session.data(from: url)
        return delegate.certificates
    }
}
