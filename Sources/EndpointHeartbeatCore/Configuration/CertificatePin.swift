import Foundation

public struct CertificatePin: Codable, Sendable, Equatable {
    public let id: String
    public let role: CertificateRole
    public let spkiSHA256Base64: String
    public let state: CertificatePinState
    public let retireAfter: Date?

    public init(
        id: String,
        role: CertificateRole,
        spkiSHA256Base64: String,
        state: CertificatePinState = .active,
        retireAfter: Date? = nil
    ) {
        self.id = id
        self.role = role
        self.spkiSHA256Base64 = spkiSHA256Base64
        self.state = state
        self.retireAfter = retireAfter
    }

    private enum CodingKeys: String, CodingKey {
        case id, role, spkiSHA256Base64, state, retireAfter
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        role = try values.decode(CertificateRole.self, forKey: .role)
        spkiSHA256Base64 = try values.decode(String.self, forKey: .spkiSHA256Base64)
        state = try values.decodeIfPresent(CertificatePinState.self, forKey: .state) ?? .active
        retireAfter = try values.decodeIfPresent(Date.self, forKey: .retireAfter)
    }
}
