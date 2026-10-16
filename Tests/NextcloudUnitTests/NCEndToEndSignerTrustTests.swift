// SPDX-FileCopyrightText: 2026 rima Pflege GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

import Foundation
import Testing
@testable import Nextcloud

@Suite("Explicit E2EE signer trust", .serialized)
struct NCEndToEndSignerTrustTests {
    @Test("Fingerprints bind public keys and survive certificate renewal")
    func fingerprints() throws {
        let first = try #require(NCEndToEndSignerTrust.fingerprint(certificate: NCEndToEndSecurityFixtures.certificate))
        #expect(first == NCEndToEndSignerTrust.fingerprint(certificate: NCEndToEndSecurityFixtures.renewedCertificate))
        #expect(first != NCEndToEndSignerTrust.fingerprint(certificate: NCEndToEndSecurityFixtures.otherCertificate))
        #expect(first.split(separator: ":").count == 32)
        #expect(NCEndToEndSignerTrust.fingerprint(certificate: "invalid PEM") == nil)
        #expect(NCEndToEndSignerTrust.fingerprint(certificate: "") == nil)
    }

    @MainActor @Test("Cancellation and malformed approvals never persist trust")
    func rejectedDecision() {
        let account = "signer-rejected-" + UUID().uuidString
        defer { NCPreferences().clearAllKeysEndToEnd(account: account) }
        #expect(!NCEndToEndSignerTrust.recordDecision(false, account: account, rootID: "root", certificate: NCEndToEndSecurityFixtures.certificate))
        #expect(!NCEndToEndSignerTrust.recordDecision(true, account: account, rootID: "root", certificate: "invalid"))
        #expect(!NCEndToEndSignerTrust.recordDecision(true, account: account, rootID: "", certificate: NCEndToEndSecurityFixtures.certificate))
        #expect(NCEndToEndSignerTrust.certificates(account: account, rootID: "root").isEmpty)
    }

    @MainActor @Test("Approvals stay scoped to account and root; local removal clears them")
    func scopedDecision() {
        let account = "signer-approved-" + UUID().uuidString
        let other = account + "_other"
        defer {
            NCPreferences().clearAllKeysEndToEnd(account: account)
            NCPreferences().clearAllKeysEndToEnd(account: other)
        }
        #expect(NCEndToEndSignerTrust.recordDecision(true, account: account, rootID: "root", certificate: NCEndToEndSecurityFixtures.certificate))
        #expect(NCEndToEndSignerTrust.certificates(account: account, rootID: "root").count == 1)
        #expect(NCEndToEndSignerTrust.certificates(account: other, rootID: "root").isEmpty)
        #expect(NCEndToEndSignerTrust.certificates(account: account, rootID: "root_other").isEmpty)
        #expect(NCEndToEndSignerTrust.recordDecision(true, account: account, rootID: "root", certificate: NCEndToEndSecurityFixtures.renewedCertificate))
        #expect(NCEndToEndSignerTrust.certificates(account: account, rootID: "root").count == 1)
        NCPreferences().clearCurrentKeysEndToEnd(account: account)
        #expect(NCEndToEndSignerTrust.certificates(account: account, rootID: "root").count == 1)
        NCPreferences().clearAllKeysEndToEnd(account: account)
        #expect(NCEndToEndSignerTrust.certificates(account: account, rootID: "root").isEmpty)
    }
}
