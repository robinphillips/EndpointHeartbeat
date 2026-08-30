import Darwin
import EndpointHeartbeatCore
import Foundation

@main
enum EndpointHeartbeatCommand {
    static func main() async {
        do {
            try await run(Array(CommandLine.arguments.dropFirst()))
        } catch {
            FileHandle.standardError.write(Data("Error: \(error)\n".utf8))
            exit(EXIT_FAILURE)
        }
    }

    private static func run(_ arguments: [String]) async throws {
        guard let command = arguments.first else {
            printUsage()
            exit(EXIT_FAILURE)
        }

        switch command {
        case "check":
            let configuration = try ConfigurationLoader.load(from: configURL(in: arguments))
            let results = await Heartbeat.checkAll(configuration.endpoints)
            let report = HeartbeatReport(results: results)
            if let reportURL = outputURL(for: "--report", in: arguments) {
                try report.writeJSON(to: reportURL)
            }
            if let reportURL = outputURL(for: "--markdown-report", in: arguments) {
                try report.writeMarkdown(to: reportURL)
            }
            for result in results {
                let marker = result.passed ? "✓" : "✗"
                print("\(marker) \(result.endpoint.name): \(result.observedOutcome.description) (expected \(result.endpoint.expectedOutcome.rawValue))")
                for warning in result.warnings {
                    print("  ⚠ \(warning.description)")
                }
            }
            let failures = results.filter { !$0.passed }.count
            let marker = failures == 0 ? "✓" : "✗"
            print("\n\(marker) \(results.count - failures)/\(results.count) checks passed")
            if failures > 0 { exit(EXIT_FAILURE) }

        case "validate":
            let configuration = try ConfigurationLoader.load(from: configURL(in: arguments))
            print("Valid configuration: \(configuration.endpoints.count) endpoints")

        case "inspect":
            guard arguments.count == 2, let url = URL(string: arguments[1]), url.scheme == "https" else {
                throw CLIError.invalidInspectURL
            }
            let certificates = try await CertificateInspector.inspect(url)
            for certificate in certificates {
                print("\(certificate.role.rawValue): \(certificate.subject)\n  SHA-256: \(certificate.sha256)")
                if let notAfter = certificate.notAfter {
                    print("  Not after: \(ISO8601DateFormatter().string(from: notAfter))")
                }
            }

        case "help", "--help", "-h":
            printUsage()

        default:
            throw CLIError.unknownCommand(command)
        }
    }

    private static func configURL(in arguments: [String]) throws -> URL {
        guard let url = outputURL(for: "--config", in: arguments) else {
            throw CLIError.missingConfig
        }
        return url
    }

    private static func outputURL(for flag: String, in arguments: [String]) -> URL? {
        guard let flagIndex = arguments.firstIndex(of: flag), arguments.indices.contains(flagIndex + 1) else {
            return nil
        }
        return URL(fileURLWithPath: arguments[flagIndex + 1])
    }

    private static func printUsage() {
        print("""
        Usage:
          endpoint-heartbeat check --config <file.json> [--report <file.json>] [--markdown-report <file.md>]
          endpoint-heartbeat validate --config <file.json>
          endpoint-heartbeat inspect <https-url>
        """)
    }
}
