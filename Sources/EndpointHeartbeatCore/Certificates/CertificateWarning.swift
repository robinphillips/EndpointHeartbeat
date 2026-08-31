import Foundation

public enum CertificateWarning: Equatable, Sendable {
    case expiring(pinID: String, role: CertificateRole, notAfter: Date)

    public var description: String {
        switch self {
        case let .expiring(pinID, role, notAfter):
            "certificate pin \(pinID) (\(role.rawValue)) expires \(ISO8601DateFormatter().string(from: notAfter))"
        }
    }
}
