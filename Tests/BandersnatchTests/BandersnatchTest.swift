import Foundation
import Testing

@testable import Bandersnatch

@Suite struct BandersnatchTests {
	@Test func BandersnatchRustCallWorks() throws {
		ring_context()
	}
}
