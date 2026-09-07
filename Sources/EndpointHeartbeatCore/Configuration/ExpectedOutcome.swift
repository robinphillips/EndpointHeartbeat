public enum ExpectedOutcome: String, Codable, Sendable {
    case success
    case trustFailure
    case systemTrustFailure
}
