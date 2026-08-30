import Foundation

public struct CertificatePin: Codable, Sendable, Equatable {
    public let id: String
    public let role: CertificateRole
    public let sha256: String
    public let state: CertificatePinState
    public let retireAfter: Date?

    public init(
        id: String,
        role: CertificateRole,
        sha256: String,
        state: CertificatePinState = .active,
        retireAfter: Date? = nil
    ) {
        self.id = id
        self.role = role
        self.sha256 = sha256
        self.state = state
        self.retireAfter = retireAfter
    }

    private enum CodingKeys: String, CodingKey {
        case id, role, sha256, state, retireAfter
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        role = try values.decode(CertificateRole.self, forKey: .role)
        sha256 = try values.decode(String.self, forKey: .sha256)
        state = try values.decodeIfPresent(CertificatePinState.self, forKey: .state) ?? .active
        retireAfter = try values.decodeIfPresent(Date.self, forKey: .retireAfter)
    }
}
