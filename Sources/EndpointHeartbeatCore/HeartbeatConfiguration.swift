public struct HeartbeatConfiguration: Codable, Sendable {
    public let endpoints: [Endpoint]

    public init(endpoints: [Endpoint]) {
        self.endpoints = endpoints
    }
}
