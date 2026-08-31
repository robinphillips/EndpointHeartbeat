import EndpointHeartbeatCore
import Foundation

struct HeartbeatReportPin: Encodable {
    let id: String
    let role: String
    let sha256: String
    let state: String
    let retireAfter: Date?

    init(_ pin: CertificatePin) {
        id = pin.id
        role = pin.role.rawValue
        sha256 = pin.sha256
        state = pin.state.rawValue
        retireAfter = pin.retireAfter
    }
}
