public enum ObservedOutcome: Equatable, Sendable {
    case success(statusCode: Int)
    case trustFailure(String)
    case httpFailure(statusCode: Int)
    case transportFailure(String)

    public var description: String {
        switch self {
        case let .success(statusCode): "HTTP \(statusCode)"
        case let .trustFailure(message): "trust failure: \(message)"
        case let .httpFailure(statusCode): "unexpected HTTP \(statusCode)"
        case let .transportFailure(message): "transport failure: \(message)"
        }
    }

    var expectedCategory: ExpectedOutcome? {
        switch self {
        case .success: .success
        case .trustFailure: .trustFailure
        case .httpFailure, .transportFailure: nil
        }
    }
}
