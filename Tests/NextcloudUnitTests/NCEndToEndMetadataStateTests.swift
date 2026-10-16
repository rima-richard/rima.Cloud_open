// SPDX-FileCopyrightText: Nextcloud GmbH
// SPDX-FileCopyrightText: 2026 Richard Gittler
// SPDX-License-Identifier: GPL-3.0-or-later

import Foundation
import Gzip
import RealmSwift
import Testing
@testable import Nextcloud

@Suite("Authenticated E2EE metadata state")
struct NCEndToEndMetadataStateTests {
    private let account = "metadata-state-test"
    private let rootID = "root"
    private let serverUrl = "https://example.test/remote.php/dav/files/local/root"
    private let key = Data(repeating: 0x42, count: 16)

    private func realm() throws -> Realm {
        try Realm(configuration: .init(inMemoryIdentifier: UUID().uuidString, objectTypes: [
            tableE2eUsers.self, tableE2eCounter.self, tableE2eMetadata.self, tableE2eMetadata12.self, tableDirectory.self,
            tableE2eEncryption.self, tableMetadata.self, tableMetadataTag.self, NCKeyValue.self
        ]))
    }

    private func keySet(certificate: String = NCEndToEndSecurityFixtures.certificate) throws -> NCEndToEndKeySet {
        try #require(NCEndToEndKeySet(certificate: certificate, privateKey: NCEndToEndSecurityFixtures.privateKey,
                                     publicKey: "server-key-is-not-a-user-trust-anchor", passphrase: nil, identifier: "selected-archived-key"))
    }

    private func cachedUser(_ userId: String, certificate: String, authenticated: Bool) -> tableE2eUsers {
        let row = tableE2eUsers(account: account, ocIdServerUrl: rootID, userId: userId)
        row.certificate = certificate
        row.metadataKey = userId == "local" ? key : nil
        row.authenticated = authenticated
        row.serverUrl = serverUrl
        return row
    }

    private func envelope(counter: Int = 2, sharedSigner: Bool = false, badChecksum: Bool = false,
                          badCiphertext: Bool = false, badFiledrop: Bool = false,
                          child: Bool = false) throws -> (json: String, signature: String) {
        let crypto = try #require(NCEndToEndEncryption.shared())
        let file = NCEndToEndMetadata.E2eeV2.Metadata.ciphertext.Files(
            authenticationTag: Data(repeating: 1, count: 16).base64EncodedString(), filename: "private.txt",
            key: key.base64EncodedString(), mimetype: "text/plain", nonce: Data(repeating: 2, count: 12).base64EncodedString())
        let checksum = try #require(crypto.createSHA256(key))
        let payload = NCEndToEndMetadata.E2eeV2.Metadata.ciphertext(counter: counter, deleted: false,
            keyChecksums: [badChecksum ? "invalid-checksum" : checksum], files: ["encrypted-file": file], folders: ["encrypted-folder": "Private"])
        var nonce: NSString?
        var tag: NSString?
        let ciphertext = try #require(crypto.encryptPayloadFile(try JSONEncoder().encode(payload).gzipped(),
            key: (badCiphertext ? Data(repeating: 0x43, count: 16) : key).base64EncodedString(),
            initializationVector: &nonce, authenticationTag: &tag))
        let metadata = NCEndToEndMetadata.E2eeV2.Metadata(ciphertext: ciphertext,
            nonce: try #require(nonce as? String), authenticationTag: try #require(tag as? String))
        let localEncryptedKey = try #require(crypto.encryptAsymmetricData(key, certificate: NCEndToEndSecurityFixtures.certificate))
        let otherEncryptedKey = try #require(crypto.encryptAsymmetricData(key, certificate: NCEndToEndSecurityFixtures.otherCertificate))
        let users: [NCEndToEndMetadata.E2eeV2.Users] = child ? [] : [
            .init(userId: "local", certificate: NCEndToEndSecurityFixtures.certificate, encryptedMetadataKey: localEncryptedKey.base64EncodedString()),
            .init(userId: "owner", certificate: NCEndToEndSecurityFixtures.otherCertificate, encryptedMetadataKey: otherEncryptedKey.base64EncodedString())
        ]
        var dropNonce: NSString?
        var dropTag: NSString?
        let dropCiphertext = try #require(crypto.encryptPayloadFile(try JSONEncoder().encode(file).gzipped(),
            key: key.base64EncodedString(), initializationVector: &dropNonce, authenticationTag: &dropTag))
        let filedrop = NCEndToEndMetadata.E2eeV2.Filedrop(ciphertext: badFiledrop ? "malformed" : dropCiphertext,
            nonce: try #require(dropNonce as? String), authenticationTag: try #require(dropTag as? String),
            users: [.init(userId: "local", encryptedFiledropKey: localEncryptedKey.base64EncodedString())])
        let envelope = NCEndToEndMetadata.E2eeV2(metadata: metadata, users: users, filedrop: ["drop-file": filedrop], version: "2.0")
        let signed = NCEndToEndMetadata.E2eeV2Signature(metadata: .init(ciphertext: metadata.ciphertext,
            nonce: metadata.nonce, authenticationTag: metadata.authenticationTag),
            users: users.map { .init(userId: $0.userId, certificate: $0.certificate, encryptedMetadataKey: $0.encryptedMetadataKey) }, version: "2.0")
        let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(signed))
        let canonical = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        let signature = try #require(crypto.generateSignatureCMS(Data(canonical.base64EncodedString().utf8),
            certificate: sharedSigner ? NCEndToEndSecurityFixtures.otherCertificate : NCEndToEndSecurityFixtures.certificate,
            privateKey: sharedSigner ? NCEndToEndSecurityFixtures.otherPrivateKey : NCEndToEndSecurityFixtures.privateKey,
            userId: sharedSigner ? "owner" : "local"))
        return (String(decoding: try JSONEncoder().encode(envelope), as: UTF8.self), signature.base64EncodedString())
    }

    private func prepare(_ envelope: (json: String, signature: String), users: [tableE2eUsers] = [],
                         certificates: [String] = [], saved: Int? = nil, child: Bool = false,
                         selectedKey: NCEndToEndKeySet? = nil) throws -> NCEndToEndMetadata.PreparedMetadataV2 {
        try NCEndToEndMetadata().prepareMetadataV2(envelope.json, signature: envelope.signature,
            account: account, userId: "local", serverUrl: serverUrl, ocIdServerUrl: rootID,
            isDirectoryTop: !child, keySet: selectedKey ?? keySet(), cachedUsers: users,
            trustedCertificates: certificates, savedCounter: saved)
    }

    private func seed(_ realm: Realm) throws {
        let display = tableMetadata()
        display.account = account
        display.ocId = "display"
        display.serverUrl = serverUrl
        display.fileName = "encrypted-file"
        display.fileNameView = "unchanged.txt"
        try realm.write {
            realm.add(display)
            realm.add(cachedUser("injected", certificate: NCEndToEndSecurityFixtures.otherCertificate, authenticated: false))
            realm.add(tableE2eCounter(account: account, ocIdServerUrl: rootID, counter: 1))
        }
    }

    private func expectSeedUnchanged(_ realm: Realm) {
        #expect(realm.objects(tableE2eUsers.self).count == 1)
        #expect(realm.objects(tableE2eUsers.self).first?.userId == "injected")
        #expect(realm.objects(tableE2eUsers.self).first?.authenticated == false)
        #expect(realm.objects(tableE2eCounter.self).first?.counter == 1)
        #expect(realm.objects(tableE2eMetadata.self).isEmpty)
        #expect(realm.objects(tableE2eEncryption.self).isEmpty)
        #expect(realm.objects(tableMetadata.self).first?.fileNameView == "unchanged.txt")
    }

    @Test("Missing or invalid signatures leave all recipient, filedrop, file and display state unchanged")
    func signatureFailuresDoNotWrite() throws {
        let realm = try realm()
        try seed(realm)
        let valid = try envelope()
        for signature in ["", "not-a-signature"] {
            #expect(throws: (any Error).self) {
                let prepared = try prepare((valid.json, signature))
                try realm.write { try NCManageDatabase.applyE2eeSnapshot(prepared.snapshot, in: realm) }
            }
            expectSeedUnchanged(realm)
        }
    }

    @Test("A mathematically valid unknown signer cannot prompt or write before checksum, main payload and filedrop validation")
    func corruptAuthenticatedPayloadsDoNotWrite() throws {
        let realm = try realm()
        try seed(realm)
        let invalid = [
            try envelope(sharedSigner: true, badChecksum: true),
            try envelope(sharedSigner: true, badCiphertext: true),
            try envelope(sharedSigner: true, badFiledrop: true)
        ]
        for envelope in invalid {
            #expect(throws: (any Error).self) {
                let prepared = try prepare(envelope)
                try realm.write { try NCManageDatabase.applyE2eeSnapshot(prepared.snapshot, in: realm) }
            }
            expectSeedUnchanged(realm)
        }
    }

    @Test("Incoming users and historical cache certificates identify a confirmation candidate without granting trust")
    func sharedSignerNeedsIndependentConfirmation() throws {
        let envelope = try envelope(sharedSigner: true)
        let historical = cachedUser("owner", certificate: NCEndToEndSecurityFixtures.otherCertificate, authenticated: false)
        let candidate = try prepare(envelope, users: [historical])
        #expect(candidate.signerToConfirm?.userId == "owner")
        #expect(candidate.signerToConfirm?.certificate == NCEndToEndSecurityFixtures.otherCertificate)
        let confirmed = try prepare(envelope, certificates: [NCEndToEndSecurityFixtures.otherCertificate])
        #expect(confirmed.signerToConfirm == nil)
        #expect(confirmed.snapshot.recipients?.first(where: { $0.userId == "local" })?.metadataKey == key)
    }

    @Test("The selected archived local certificate authorizes its own root, including a renewed certificate with the same key")
    func selectedArchivedCertificateAuthorizesRoot() throws {
        let prepared = try prepare(envelope(), selectedKey: keySet(certificate: NCEndToEndSecurityFixtures.renewedCertificate))
        #expect(prepared.signerToConfirm == nil)
        #expect(prepared.snapshot.files.count == 3)
    }

    @Test("Children inherit only authenticated root participants")
    func childRequiresAuthenticatedRoot() throws {
        let child = try envelope(sharedSigner: true, child: true)
        let local = cachedUser("local", certificate: NCEndToEndSecurityFixtures.certificate, authenticated: true)
        let owner = cachedUser("owner", certificate: NCEndToEndSecurityFixtures.otherCertificate, authenticated: true)
        #expect(try prepare(child, users: [local, owner], child: true).signerToConfirm == nil)
        owner.authenticated = false
        #expect(throws: (any Error).self) { try prepare(child, users: [local, owner], child: true) }
        local.authenticated = false
        #expect(throws: (any Error).self) {
            try prepare(child, users: [local, owner], certificates: [NCEndToEndSecurityFixtures.otherCertificate], child: true)
        }
    }

    @Test("One transaction replaces recipients and applies all authenticated metadata")
    func authoritativeSnapshotReplacesInjectedRecipients() throws {
        let realm = try realm()
        try seed(realm)
        let snapshot = try prepare(envelope()).snapshot
        try realm.write { try NCManageDatabase.applyE2eeSnapshot(snapshot, in: realm) }
        #expect(Set(realm.objects(tableE2eUsers.self).map(\.userId)) == ["local", "owner"])
        let allAuthenticated = realm.objects(tableE2eUsers.self).allSatisfy { $0.authenticated }
        #expect(allAuthenticated)
        #expect(realm.objects(tableE2eEncryption.self).count == 3)
        #expect(realm.objects(tableE2eMetadata.self).first?.folders["encrypted-folder"] == "Private")
        #expect(realm.objects(tableMetadata.self).first?.fileNameView == "private.txt")
        #expect(realm.objects(tableE2eCounter.self).first?.counter == 2)
    }

    @Test("Repeated replay stays rejected, equal counters reload, and a transaction rechecks intervening progress")
    func counterNeverRollsBack() throws {
        let realm = try realm()
        let earlier = try prepare(envelope(counter: 2)).snapshot
        let later = try prepare(envelope(counter: 3)).snapshot
        try realm.write { try NCManageDatabase.applyE2eeSnapshot(later, in: realm) }
        for _ in 0..<2 {
            #expect(throws: NCManageDatabase.E2eeStateError.self) {
                try realm.write { try NCManageDatabase.applyE2eeSnapshot(earlier, in: realm) }
            }
            #expect(realm.objects(tableE2eCounter.self).first?.counter == 3)
        }
        try realm.write { try NCManageDatabase.applyE2eeSnapshot(later, in: realm) }
        #expect(realm.objects(tableE2eCounter.self).first?.counter == 3)
        #expect(throws: NCManageDatabase.E2eeStateError.self) { try prepare(envelope(counter: 2), saved: 3) }
    }

    @Test("A transaction failure rolls back recipients, encryption rows, display data and counter together")
    func transactionFailureRollsBackEverything() throws {
        let realm = try realm()
        try seed(realm)
        let snapshot = try prepare(envelope()).snapshot
        #expect(throws: NCManageDatabase.E2eeStateError.self) {
            try realm.write {
                try NCManageDatabase.applyE2eeSnapshot(snapshot, in: realm)
                throw NCManageDatabase.E2eeStateError.staleCounter
            }
        }
        expectSeedUnchanged(realm)
    }

    @Test("Rewrapping excludes historical injected recipients and preserves explicit sharing add/remove")
    func outgoingRecipientsUseAuthenticatedProvenance() throws {
        let decoder = NCEndToEndMetadata()
        let historical = cachedUser("injected", certificate: NCEndToEndSecurityFixtures.otherCertificate, authenticated: false)
        let authenticated = cachedUser("owner", certificate: NCEndToEndSecurityFixtures.otherCertificate, authenticated: true)
        let recipients = try decoder.prepareRecipientsV2(cachedUsers: [historical, authenticated], key: key,
            userId: "local", certificate: NCEndToEndSecurityFixtures.certificate, addUserId: "selected",
            addCertificate: NCEndToEndSecurityFixtures.otherCertificate, removeUserId: "owner")
        #expect(Set(recipients.map(\.userId)) == ["local", "selected"])
        let selected = try #require(recipients.first(where: { $0.userId == "selected" }))
        let encodedKey = try #require(selected.encryptedMetadataKey)
        let encrypted = try #require(Data(base64Encoded: encodedKey))
        #expect(NCEndToEndEncryption.shared().decryptAsymmetricData(encrypted, privateKey: NCEndToEndSecurityFixtures.otherPrivateKey) == key)
    }

    @Test("The asynchronous transaction reports failures instead of claiming that partial writes committed")
    func transactionReportsFailure() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let configuration = Realm.Configuration(fileURL: directory.appendingPathComponent("state.realm"), objectTypes: [tableE2eCounter.self])
        let core = NCManageDatabaseCore()
        try await core.performRealmTransactionAsync(configuration: configuration) { realm in
            realm.add(tableE2eCounter(account: account, ocIdServerUrl: rootID, counter: 1))
        }
        do {
            try await core.performRealmTransactionAsync(configuration: configuration) { realm in
                realm.add(tableE2eCounter(account: account, ocIdServerUrl: rootID, counter: 2), update: .all)
                throw NCManageDatabase.E2eeStateError.staleCounter
            }
            Issue.record("The failing write was incorrectly reported as committed.")
        } catch NCManageDatabase.E2eeStateError.staleCounter {
            let persistedCounter = try await MainActor.run {
                let reopened = try Realm(configuration: configuration)
                return reopened.objects(tableE2eCounter.self).first?.counter
            }
            #expect(persistedCounter == 1)
        }
    }

    @Test("A freshly initialized zero counter works and increment overflow fails closed")
    func counterBoundaries() throws {
        #expect(NCEndToEndMetadata.nextMetadataCounter(nil) == 1)
        #expect(NCEndToEndMetadata.nextMetadataCounter(0) == 1)
        #expect(NCEndToEndMetadata.nextMetadataCounter(Int.max) == nil)
        #expect(NCEndToEndMetadata.nextMetadataCounter(-1) == nil)
        try NCManageDatabase.checkE2eeCounter(0, saved: 0)
        #expect(throws: NCManageDatabase.E2eeStateError.self) { try NCManageDatabase.checkE2eeCounter(-1, saved: nil) }
    }
    private func legacyEnvelope(version: Double = 1.2, corrupt: Bool = false) throws -> String {
        let crypto = try #require(NCEndToEndEncryption.shared())
        // Anyone with the public certificate can choose and wrap this key. This is
        // deliberately unsigned and must never be accepted for a known V2 folder.
        let encodedKey = Data(Data(key.base64EncodedString().utf8).base64EncodedString().utf8)
        let wrapped = try #require(crypto.encryptAsymmetricData(encodedKey, certificate: NCEndToEndSecurityFixtures.certificate))
        let file = NCEndToEndMetadata.E2eeV1.Encrypted(key: key.base64EncodedString(), filename: "legacy.txt", mimetype: "text/plain")
        let plaintext = Data(try JSONEncoder().encode(file).base64EncodedString().utf8)
        let encrypted = try #require(crypto.encryptPayloadFile(plaintext, key: key.base64EncodedString()))
        let ciphertext = corrupt ? "corrupt" : encrypted
        let nonce = Data(repeating: 2, count: 12).base64EncodedString()
        let tag = Data(repeating: 3, count: 16).base64EncodedString()
        if version == 1.1 {
            let envelope = NCEndToEndMetadata.E2eeV1(metadata: .init(metadataKeys: ["0": wrapped.base64EncodedString()], version: version),
                files: ["legacy-file": .init(initializationVector: nonce, authenticationTag: tag, metadataKey: 0, encrypted: ciphertext)])
            return String(decoding: try JSONEncoder().encode(envelope), as: UTF8.self)
        }
        let checksum = try #require(crypto.createSHA256(Data(("legacy-file" + wrapped.base64EncodedString()).utf8)))
        let envelope = NCEndToEndMetadata.E2eeV12(metadata: .init(metadataKey: wrapped.base64EncodedString(), version: version, checksum: checksum),
            files: ["legacy-file": .init(initializationVector: nonce, authenticationTag: tag, encrypted: ciphertext)], filedrop: nil)
        return String(decoding: try JSONEncoder().encode(envelope), as: UTF8.self)
    }

    @Test("Valid V1.1 and V1.2 folders still prepare and commit through the real legacy boundary")
    func genuineLegacyCompatibility() throws {
        for version in [1.1, 1.2] {
            let realm = try realm()
            let requiresV2 = try NCManageDatabase.requiresE2eeV2(account: account, serverUrl: serverUrl, ocIdServerUrl: rootID, in: realm)
            #expect(!requiresV2)
            let prepared = try NCEndToEndMetadata().prepareLegacyMetadata(legacyEnvelope(version: version), account: account,
                serverUrl: serverUrl, ocIdServerUrl: rootID, keySet: keySet(), requiresV2: requiresV2)
            try realm.write { try NCManageDatabase.applyLegacyE2eeSnapshot(prepared, in: realm) }
            #expect(realm.objects(tableE2eEncryption.self).first?.fileName == "legacy.txt")
            #expect(realm.objects(tableE2eEncryption.self).first?.version == String(version))
            #expect(realm.objects(tableE2eEncryption.self).first?.authenticated == false)
            #expect(realm.objects(tableE2eMetadata12.self).first?.version == version)
        }
    }

    @Test("Unsigned public-certificate legacy packets cannot downgrade a V2 root or any child")
    func knownV2RejectsLegacyDispatchAndEncoding() throws {
        let realm = try realm()
        let root = tableDirectory()
        root.account = account
        root.ocId = rootID
        root.serverUrl = serverUrl
        try realm.write {
            realm.add(root)
            realm.add(tableE2eCounter(account: account, ocIdServerUrl: rootID, counter: 0, requiresV2: true))
        }
        for target in [serverUrl, serverUrl + "/child"] {
            let requiresV2 = try NCManageDatabase.requiresE2eeV2(account: account, serverUrl: target, ocIdServerUrl: target == serverUrl ? rootID : "child", in: realm)
            #expect(requiresV2)
            #expect(throws: (any Error).self) {
                try NCEndToEndMetadata().prepareLegacyMetadata(legacyEnvelope(), account: account, serverUrl: target,
                    ocIdServerUrl: rootID, keySet: keySet(), requiresV2: requiresV2)
            }
            #expect(throws: (any Error).self) { try NCEndToEndMetadata.encodingFormat(version: "1.2", requiresV2: requiresV2) }
        }
        #expect(realm.objects(tableE2eEncryption.self).isEmpty)
    }

    @Test("Hybrid envelopes are rejected before any Codable version can ignore the other format")
    func hybridEnvelopeIsRejected() throws {
        let valid = try envelope()
        var object = try #require(JSONSerialization.jsonObject(with: Data(valid.json.utf8)) as? [String: Any])
        var metadata = try #require(object["metadata"] as? [String: Any])
        metadata["metadataKey"] = "attacker-wrapped-key"
        metadata["metadataKeys"] = ["0": "attacker-wrapped-key"]
        metadata["version"] = 1.2
        object["metadata"] = metadata
        let hybrid = try JSONSerialization.data(withJSONObject: object)
        #expect(throws: (any Error).self) { try NCEndToEndMetadata.metadataFormat(hybrid, requiresV2: false) }
        #expect(throws: (any Error).self) { try prepare((String(decoding: hybrid, as: UTF8.self), valid.signature)) }
    }

    @Test("A V2 upgrade between legacy preparation and commit blocks every legacy write")
    func legacyCommitRechecksStickyVersion() throws {
        let realm = try realm()
        let prepared = try NCEndToEndMetadata().prepareLegacyMetadata(legacyEnvelope(), account: account, serverUrl: serverUrl,
            ocIdServerUrl: rootID, keySet: keySet(), requiresV2: false)
        try realm.write { realm.add(tableE2eCounter(account: account, ocIdServerUrl: rootID, counter: 0, requiresV2: true)) }
        #expect(throws: NCManageDatabase.E2eeStateError.self) {
            try realm.write { try NCManageDatabase.applyLegacyE2eeSnapshot(prepared, in: realm) }
        }
        #expect(realm.objects(tableE2eEncryption.self).isEmpty)
        #expect(realm.objects(tableE2eMetadata12.self).isEmpty)
        #expect(realm.objects(tableE2eCounter.self).first?.requiresV2 == true)
    }

    @Test("Malformed legacy ciphertext cannot erase existing valid legacy state")
    func corruptLegacyDoesNotWrite() throws {
        let realm = try realm()
        let valid = try NCEndToEndMetadata().prepareLegacyMetadata(legacyEnvelope(), account: account, serverUrl: serverUrl,
            ocIdServerUrl: rootID, keySet: keySet(), requiresV2: false)
        try realm.write { try NCManageDatabase.applyLegacyE2eeSnapshot(valid, in: realm) }
        #expect(throws: (any Error).self) {
            let invalid = try NCEndToEndMetadata().prepareLegacyMetadata(legacyEnvelope(corrupt: true), account: account,
                serverUrl: serverUrl, ocIdServerUrl: rootID, keySet: keySet(), requiresV2: false)
            try realm.write { try NCManageDatabase.applyLegacyE2eeSnapshot(invalid, in: realm) }
        }
        #expect(realm.objects(tableE2eEncryption.self).count == 1)
        #expect(realm.objects(tableE2eEncryption.self).first?.fileName == "legacy.txt")
    }

    @Test("Historical file keys cannot be resigned; snapshots remove poison and obsolete remote rows while preserving local pending work")
    func fileProvenanceAndAuthoritativeReconciliation() throws {
        let realm = try realm()
        let poisoned = tableE2eEncryption(account: account, ocIdServerUrl: rootID, fileNameIdentifier: "poison")
        poisoned.serverUrl = serverUrl
        poisoned.version = "2"
        let oldRemote = tableE2eEncryption(account: account, ocIdServerUrl: rootID, fileNameIdentifier: "removed")
        oldRemote.serverUrl = serverUrl
        oldRemote.version = "2"
        oldRemote.authenticated = true
        let pending = tableE2eEncryption(account: account, ocIdServerUrl: rootID, fileNameIdentifier: "pending")
        pending.serverUrl = serverUrl
        pending.locallyGenerated = true
        pending.fileName = "pending.txt"
        #expect(!poisoned.isUsableForE2eeV2)
        #expect(throws: (any Error).self) { try NCEndToEndMetadata.outgoingEncryptionRowsV2([poisoned, pending]) }
        let outgoing = try NCEndToEndMetadata.outgoingEncryptionRowsV2([pending, oldRemote])
        #expect(outgoing.count == 2)
        try realm.write { realm.add([poisoned, oldRemote, pending]) }
        let snapshot = try prepare(envelope()).snapshot
        try realm.write { try NCManageDatabase.applyE2eeSnapshot(snapshot, in: realm) }
        #expect(realm.objects(tableE2eEncryption.self).filter("fileNameIdentifier == 'poison' OR fileNameIdentifier == 'removed'").isEmpty)
        #expect(realm.objects(tableE2eEncryption.self).filter("locallyGenerated == true").first?.fileName == "pending.txt")
        #expect(realm.objects(tableE2eEncryption.self).filter("authenticated == true").count == 3)
    }

    @Test("Remote snapshots acknowledge matching local pending keys but preserve newer unacknowledged replacements")
    func pendingKeysArePreservedUntilAcknowledged() throws {
        let realm = try realm()
        let snapshot = try prepare(envelope()).snapshot
        let file = try #require(snapshot.files.first(where: { $0.identifier == "encrypted-file" }))
        let pending = tableE2eEncryption(account: account, ocIdServerUrl: rootID, fileNameIdentifier: file.identifier)
        pending.serverUrl = serverUrl
        pending.locallyGenerated = true
        pending.fileName = "new-local.txt"
        pending.key = "new-local-key"
        try realm.write { realm.add(pending) }
        try realm.write { try NCManageDatabase.applyE2eeSnapshot(snapshot, in: realm) }
        #expect(pending.key == "new-local-key")
        #expect(pending.locallyGenerated)
        try realm.write {
            pending.fileName = file.name
            pending.key = file.key
            pending.initializationVector = file.nonce
            pending.authenticationTag = file.authenticationTag
            pending.mimeType = file.mimeType
        }
        try realm.write { try NCManageDatabase.applyE2eeSnapshot(snapshot, in: realm) }
        #expect(pending.authenticated)
        #expect(!pending.locallyGenerated)
    }

    @Test("Legacy counter zero is compatible only with positive legacy evidence and no explicit V2 marker")
    func legacyZeroCounterAndExplicitV2Marker() throws {
        let realm = try realm()
        let legacy = tableE2eMetadata12()
        legacy.account = account
        legacy.serverUrl = serverUrl
        legacy.version = 1.2
        let counter = tableE2eCounter(account: account, ocIdServerUrl: rootID, counter: 0)
        try realm.write { realm.add(legacy); realm.add(counter) }
        let before = try NCManageDatabase.requiresE2eeV2(account: account, serverUrl: serverUrl, ocIdServerUrl: rootID, in: realm)
        #expect(!before)
        try realm.write { counter.requiresV2 = true }
        let after = try NCManageDatabase.requiresE2eeV2(account: account, serverUrl: serverUrl, ocIdServerUrl: rootID, in: realm)
        #expect(after)
    }

    @Test("Schema upgrade retains historical keys as untrusted")
    func historicalFileKeyMigration() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let url = folder.appendingPathComponent("historical.realm")
        try autoreleasepool {
            let old = try Realm(configuration: .init(fileURL: url, schemaVersion: 423, objectTypes: [tableE2eEncryption.self]))
            let row = tableE2eEncryption(account: account, ocIdServerUrl: rootID, fileNameIdentifier: "historical")
            row.version = "2"
            row.key = "historical-key"
            try old.write { old.add(row) }
        }
        let upgraded = try Realm(configuration: .init(fileURL: url, schemaVersion: databaseSchemaVersion,
            migrationBlock: { _, _ in }, objectTypes: [tableE2eEncryption.self]))
        let row = try #require(upgraded.objects(tableE2eEncryption.self).first)
        #expect(row.key == "historical-key")
        #expect(!row.authenticated)
        #expect(!row.locallyGenerated)
        #expect(throws: (any Error).self) { try NCEndToEndMetadata.outgoingEncryptionRowsV2([row]) }
    }

    @Test("Fingerprint approval remains sticky V2 evidence before a metadata transaction commits")
    func approvedSignerPreventsLegacyFallback() throws {
        let realm = try realm()
        let pinAccount = "e2ee-pin-version-\(UUID().uuidString)"
        let preferences = NCPreferences()
        defer { preferences.clearAllKeysEndToEnd(account: pinAccount) }
        try preferences.setEndToEndApprovedSigners([NCEndToEndSecurityFixtures.certificate], account: pinAccount, rootID: rootID)
        let requiresV2 = try NCManageDatabase.requiresE2eeV2(account: pinAccount, serverUrl: serverUrl, ocIdServerUrl: rootID, in: realm)
        #expect(requiresV2)
        #expect(throws: (any Error).self) { try NCEndToEndMetadata.metadataFormat(Data(legacyEnvelope().utf8), requiresV2: requiresV2) }
    }

    @Test("Missing directory identifiers do not erase independent ancestor V2 evidence")
    func malformedDirectoryIdentifierKeepsAncestorPolicy() throws {
        let realm = try realm()
        let directory = tableDirectory()
        directory.account = account
        directory.ocId = ""
        directory.serverUrl = serverUrl
        let marker = tableE2eMetadata(account: account, ocIdServerUrl: rootID)
        marker.serverUrl = serverUrl
        try realm.write { realm.add(directory); realm.add(marker) }
        let requiresV2 = try NCManageDatabase.requiresE2eeV2(account: account, serverUrl: serverUrl + "/child", ocIdServerUrl: "", in: realm)
        #expect(requiresV2)
    }

}
