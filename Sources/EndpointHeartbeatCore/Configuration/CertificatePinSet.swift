public struct CertificatePinSet: Codable, Sendable {
    public let id: String
    public let pinIDs: [String]
    public let expectedOutcome: ExpectedOutcome

    public init(id: String, pinIDs: [String], expectedOutcome: ExpectedOutcome = .success) {
        self.id = id
        self.pinIDs = pinIDs
        self.expectedOutcome = expectedOutcome
    }

    private enum CodingKeys: String, CodingKey {
        case id, pinIDs, expectedOutcome
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        pinIDs = try values.decode([String].self, forKey: .pinIDs)
        expectedOutcome = try values.decodeIfPresent(ExpectedOutcome.self, forKey: .expectedOutcome) ?? .success
    }
}
