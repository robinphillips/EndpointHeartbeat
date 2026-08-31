import EndpointHeartbeatCore
import Foundation

struct HeartbeatReportPin: Encodable {
    let id: String
    let role: String
    let spkiSHA256Base64: String
    let state: String
    let retireAfter: Date?

    init(_ pin: CertificatePin) {
        id = pin.id
        role = pin.role.rawValue
        spkiSHA256Base64 = pin.spkiSHA256Base64
        state = pin.state.rawValue
        retireAfter = pin.retireAfter
    }
}
