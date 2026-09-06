import Foundation

public struct HeartbeatReportPin: Encodable {
    public let id: String
    public let role: String
    public let spkiSHA256Base64: String
    public let state: String
    public let retireAfter: Date?

    init(_ pin: CertificatePin) {
        id = pin.id
        role = pin.role.rawValue
        spkiSHA256Base64 = pin.spkiSHA256Base64
        state = pin.state.rawValue
        retireAfter = pin.retireAfter
    }
}
