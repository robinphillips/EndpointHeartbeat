import Foundation

public enum SystemClock {
    @TaskLocal
    private static var testDate: Date?

    public static var now: Date {
        testDate ?? Date()
    }

    @_spi(TestSupport)
    public static func withCurrentDate<T>(
        _ date: Date,
        operation: () async throws -> T
    ) async rethrows -> T {
        try await $testDate.withValue(date) {
            try await operation()
        }
    }
}
