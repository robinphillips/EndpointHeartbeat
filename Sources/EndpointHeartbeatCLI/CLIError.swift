enum CLIError: Error, CustomStringConvertible {
    case unknownCommand(String)
    case missingConfig
    case invalidInspectURL

    var description: String {
        switch self {
        case let .unknownCommand(command): "unknown command: \(command)"
        case .missingConfig: "--config <file.json> is required"
        case .invalidInspectURL: "inspect requires one HTTPS URL"
        }
    }
}
