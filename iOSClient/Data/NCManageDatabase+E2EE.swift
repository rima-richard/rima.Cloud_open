// SPDX-FileCopyrightText: Nextcloud GmbH
// SPDX-FileCopyrightText: 2023 Marino Faggiana
// SPDX-License-Identifier: GPL-3.0-or-later

import Foundation
import UIKit
import RealmSwift
import NextcloudKit

class tableE2eEncryptionLock: Object {
    @Persisted(primaryKey: true) var fileId = ""
    @Persisted var account = ""
    @Persisted var date = Date()
    @Persisted var serverUrl = ""
    @Persisted var e2eToken = ""
}

typealias tableE2eEncryption = tableE2eEncryptionV4
class tableE2eEncryptionV4: Object {
    @Persisted(primaryKey: true) var primaryKey = ""
    @Persisted var account = ""
    @Persisted var authenticationTag: String = ""
    @Persisted var blob = "files"
    @Persisted var fileName = ""
    @Persisted var fileNameIdentifier = ""
    @Persisted var key = ""
    @Persisted var initializationVector = ""
    @Persisted var metadataKey = ""
    @Persisted var metadataKeyIndex: Int = 0
    @Persisted var version: String = ""
    @Persisted var mimeType = ""
    @Persisted var ocIdServerUrl: String = ""
    @Persisted var serverUrl = ""

    // New fields default to false for historical cache entries, including schema 423.
    @Persisted var authenticated = false
    @Persisted var locallyGenerated = false

    var isUsableForE2eeV2: Bool { authenticated || locallyGenerated }

    convenience init(account: String, ocIdServerUrl: String, fileNameIdentifier: String) {
        self.init()
        self.primaryKey = account + ocIdServerUrl + fileNameIdentifier
        self.account = account
        self.ocIdServerUrl = ocIdServerUrl
        self.fileNameIdentifier = fileNameIdentifier
     }
}

// MARK: -
// MARK: Table V1, V1.2

class tableE2eMetadata12: Object {
    @Persisted(primaryKey: true) var serverUrl = ""
    @Persisted var account = ""
    @Persisted var metadataKey = ""
    @Persisted var version: Double = 0
}

// MARK: -
// MARK: Table V2

typealias tableE2eMetadata = tableE2eMetadataV2
class tableE2eMetadataV2: Object {
    @Persisted(primaryKey: true) var primaryKey = ""
    @Persisted var account = ""
    @Persisted var deleted: Bool = false
    @Persisted var folders = Map<String, String>()
    @Persisted var keyChecksums = List<String>()
    @Persisted var ocIdServerUrl: String = ""
    @Persisted var serverUrl: String = ""
    @Persisted var version: String = "2"

    convenience init(account: String, ocIdServerUrl: String) {
        self.init()
        self.account = account
        self.ocIdServerUrl = ocIdServerUrl
        self.primaryKey = account + ocIdServerUrl
     }
}

class tableE2eCounter: Object {
    @Persisted(primaryKey: true) var primaryKey: String
    @Persisted var account: String
    @Persisted var counter: Int
    @Persisted var requiresV2 = false
    @Persisted var ocIdServerUrl: String

    convenience init(account: String, ocIdServerUrl: String, counter: Int, requiresV2: Bool = false) {
        self.init()
        self.account = account
        self.ocIdServerUrl = ocIdServerUrl
        self.primaryKey = account + ocIdServerUrl
        self.counter = counter
        self.requiresV2 = requiresV2
     }
}

class tableE2eUsers: Object {
    @Persisted(primaryKey: true) var primaryKey = ""
    @Persisted var account = ""
    @Persisted var certificate = ""
    @Persisted var encryptedMetadataKey: String?
    @Persisted var metadataKey: Data?
    @Persisted var ocIdServerUrl: String = ""
    @Persisted var serverUrl: String = ""
    @Persisted var userId = ""
    // Defaults to false during migration: the old decoder stored unauthenticated input.
    @Persisted var authenticated = false

    convenience init(account: String, ocIdServerUrl: String, userId: String) {
        self.init()
        self.primaryKey = account + ocIdServerUrl + userId
        self.account = account
        self.ocIdServerUrl = ocIdServerUrl
        self.userId = userId
     }
}

extension NCManageDatabase {
    // MARK: -
    // MARK: tableE2eEncryption
    func addE2eEncryptionAsync(_ object: tableE2eEncryption) async {
        await core.performRealmWriteAsync { realm in
            realm.add(object, update: .all)
        }
    }

    /// Only callers that have just encrypted a local file or generated a folder may use this writer.
    func addLocallyGeneratedE2eEncryptionAsync(_ object: tableE2eEncryption) async throws {
        object.authenticated = false
        object.locallyGenerated = true
        try await core.performRealmTransactionAsync { realm in
            realm.add(object, update: .all)
        }
    }

    static func requiresE2eeV2(account: String, serverUrl: String, ocIdServerUrl: String, in realm: Realm) throws -> Bool {
        var ancestors: Set<String> = [serverUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))]
        if var url = URL(string: serverUrl) {
            while !url.path.isEmpty && url.path != "/" {
                let value = url.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                ancestors.insert(value)
                if let decoded = value.removingPercentEncoding { ancestors.insert(decoded) }
                let parent = url.deletingLastPathComponent()
                guard parent != url else { break }
                url = parent
            }
        }
        let urls = Array(ancestors)
        var locations: [String: String] = [:]
        for directory in realm.objects(tableDirectory.self).filter("account == %@ AND serverUrl IN %@", account, urls) where !directory.ocId.isEmpty {
            locations[directory.ocId] = directory.serverUrl
        }
        for item in realm.objects(tableMetadata.self).filter("account == %@ AND directory == true AND serverUrlFileName IN %@", account, urls) {
            if !item.ocId.isEmpty { locations[item.ocId] = item.serverUrlFileName }
        }
        if !ocIdServerUrl.isEmpty { locations[ocIdServerUrl] = serverUrl }
        let scope = Array(locations.keys)
        if !realm.objects(tableE2eMetadata.self).filter("account == %@ AND (ocIdServerUrl IN %@ OR serverUrl IN %@)", account, scope, urls).isEmpty
            || !realm.objects(tableE2eUsers.self).filter("account == %@ AND (ocIdServerUrl IN %@ OR serverUrl IN %@)", account, scope, urls).isEmpty
            || !realm.objects(tableE2eEncryption.self).filter("account == %@ AND (ocIdServerUrl IN %@ OR serverUrl IN %@) AND version BEGINSWITH '2'", account, scope, urls).isEmpty {
            return true
        }
        for counter in realm.objects(tableE2eCounter.self).filter("account == %@ AND ocIdServerUrl IN %@", account, scope) {
            if counter.requiresV2 || counter.counter > 0 { return true }
            // Old V1 uploads also wrote counter zero. Only a positively identified
            // legacy folder may retain that compatibility; a fresh zero is V2.
            let legacy = locations[counter.ocIdServerUrl].flatMap { url in
                realm.objects(tableE2eMetadata12.self).filter("account == %@ AND serverUrl == %@ AND version >= 1 AND version < 2", account, url).first
            }
            if legacy == nil { return true }
        }
        for rootID in scope {
            if try !NCPreferences().getEndToEndApprovedSigners(account: account, rootID: rootID).isEmpty { return true }
        }
        return false
    }

    func requiresE2eeV2Async(account: String, serverUrl: String, ocIdServerUrl: String) async throws -> Bool {
        try await core.performRealmReadThrowingAsync { realm in
            try Self.requiresE2eeV2(account: account, serverUrl: serverUrl, ocIdServerUrl: ocIdServerUrl, in: realm)
        }
    }

    func getUsableE2eEncryptionsAsync(account: String, serverUrl: String, ocIdServerUrl: String) async throws -> [tableE2eEncryption] {
        try await core.performRealmReadThrowingAsync { realm in
            let requiresV2 = try Self.requiresE2eeV2(account: account, serverUrl: serverUrl, ocIdServerUrl: ocIdServerUrl, in: realm)
            return realm.objects(tableE2eEncryption.self).filter("account == %@ AND serverUrl == %@", account, serverUrl)
                .filter { $0.isUsableForE2eeV2 || (!requiresV2 && $0.version.hasPrefix("1.")) }
                .map { tableE2eEncryption(value: $0) }
        }
    }

    func deleteE2eEncryptionAsync(predicate: NSPredicate) async {
        await core.performRealmWriteAsync { realm in
            let results = realm.objects(tableE2eEncryption.self)
                .filter(predicate)
            realm.delete(results)
        }
    }

    func getE2eEncryption(predicate: NSPredicate) -> tableE2eEncryption? {
        core.performRealmRead { realm in
            realm.objects(tableE2eEncryption.self)
                .filter(predicate)
                .sorted(byKeyPath: "metadataKeyIndex", ascending: false)
                .first
                .map { tableE2eEncryption(value: $0) }
        }
    }

    func getE2eEncryptionAsync(predicate: NSPredicate) async -> tableE2eEncryption? {
        await core.performRealmReadAsync { realm in
            realm.objects(tableE2eEncryption.self)
                .filter(predicate)
                .first
                .map { tableE2eEncryption(value: $0) }
        }
    }

    func getE2eEncryptionsThrowingAsync(predicate: NSPredicate) async throws -> [tableE2eEncryption] {
        try await core.performRealmReadThrowingAsync { realm in
            realm.objects(tableE2eEncryption.self).filter(predicate).map { tableE2eEncryption(value: $0) }
        }
    }

    func getE2eEncryptionsAsync(predicate: NSPredicate) async -> [tableE2eEncryption] {
        await core.performRealmReadAsync { realm in
            let results = realm.objects(tableE2eEncryption.self)
                .filter(predicate)
            return results.map { tableE2eEncryption(value: $0) }
        } ?? []
    }

    func renameFileE2eEncryptionAsync(account: String, serverUrl: String, fileNameIdentifier: String, newFileName: String, newFileNamePath: String) async {
        await core.performRealmWriteAsync { realm in
            guard let result = realm.objects(tableE2eEncryption.self)
                .filter("account == %@ AND serverUrl == %@ AND fileNameIdentifier == %@", account, serverUrl, fileNameIdentifier)
                .first else { return }

            guard try result.isUsableForE2eeV2 || (!(try Self.requiresE2eeV2(account: account, serverUrl: serverUrl, ocIdServerUrl: result.ocIdServerUrl, in: realm)) && result.version.hasPrefix("1.")) else { return }
            result.fileName = newFileName
            result.locallyGenerated = true

            realm.add(result, update: .all)
        }
    }
    // MARK: -
    // MARK: Table e2e Encryption Lock

    func getE2ETokenLockAsync(account: String, serverUrl: String) async -> tableE2eEncryptionLock? {
        await core.performRealmReadAsync { realm in
            realm.objects(tableE2eEncryptionLock.self)
                .filter("account == %@ AND serverUrl == %@", account, serverUrl)
                .first
                .map { tableE2eEncryptionLock(value: $0) }
        }
    }

    func getE2EAllTokenLockAsync(account: String) async -> [tableE2eEncryptionLock] {
        await core.performRealmReadAsync { realm in
            let results = realm.objects(tableE2eEncryptionLock.self)
                .filter("account == %@", account)
            return results.map { tableE2eEncryptionLock(value: $0) }
        } ?? []
    }

    func setE2ETokenLockAsync(account: String, serverUrl: String, fileId: String, e2eToken: String) async {
        await core.performRealmWriteAsync { realm in
            let object = tableE2eEncryptionLock()
            object.account = account
            object.fileId = fileId
            object.serverUrl = serverUrl
            object.e2eToken = e2eToken

            realm.add(object, update: .all)
        }
    }

    func deleteE2ETokenLockAsync(account: String, serverUrl: String) async {
        await core.performRealmWriteAsync { realm in
            let results = realm.objects(tableE2eEncryptionLock.self)
                .filter("account == %@ AND serverUrl == %@", account, serverUrl)
            realm.delete(results)
        }
    }

    // MARK: -
    // MARK: V1

    func getE2eMetadataAsync(account: String, serverUrl: String) async -> tableE2eMetadata12? {
        await core.performRealmReadAsync { realm in
            realm.objects(tableE2eMetadata12.self)
                .filter("account == %@ AND serverUrl == %@", account, serverUrl)
                .first
                .map { tableE2eMetadata12(value: $0) } // detached copy
        }
    }

    func setE2eMetadataAsync(account: String, serverUrl: String, ocIdServerUrl: String, metadataKey: String, version: Double) async throws {
        try await core.performRealmTransactionAsync { realm in
            guard try !Self.requiresE2eeV2(account: account, serverUrl: serverUrl, ocIdServerUrl: ocIdServerUrl, in: realm) else {
                throw E2eeStateError.versionDowngrade
            }
            let object = tableE2eMetadata12()
            object.account = account
            object.metadataKey = metadataKey
            object.serverUrl = serverUrl
            object.version = version
            realm.add(object, update: .all)
        }
    }

    // MARK: -
    // MARK: V2

    struct E2eeRecipient: Sendable {
        let userId: String
        let certificate: String
        let encryptedMetadataKey: String?
        let metadataKey: Data?
    }

    struct E2eeFile: Sendable {
        let identifier: String
        let name: String
        let authenticationTag: String
        let key: String
        let nonce: String
        let metadataKey: String
        let mimeType: String
        var contentType = ""
        var iconName = ""
        var classFile = ""
        var typeIdentifier = ""
        var blob = "files"
        var metadataKeyIndex = 0
    }

    struct E2eeLegacySnapshot: Sendable {
        let account: String
        let serverUrl: String
        let ocIdServerUrl: String
        let version: Double
        let metadataKey: String
        var files: [E2eeFile]
    }

    struct E2eeValidatedSnapshot: Sendable {
        let account: String
        let serverUrl: String
        let ocIdServerUrl: String
        let counter: Int
        let recipients: [E2eeRecipient]?
        let keyChecksums: [String]
        let deleted: Bool
        let folders: [String: String]
        let version: String
        var files: [E2eeFile]
    }

    enum E2eeStateError: Error {
        case staleCounter
        case versionDowngrade
    }

    static func checkE2eeCounter(_ incoming: Int, saved: Int?) throws {
        guard incoming >= 0, incoming >= (saved ?? 0) else {
            throw E2eeStateError.staleCounter
        }
    }

    static func replaceE2eeRecipients(_ recipients: [E2eeRecipient], account: String, serverUrl: String, rootID: String, in realm: Realm) {
        realm.delete(realm.objects(tableE2eUsers.self).filter("account == %@ AND ocIdServerUrl == %@", account, rootID))
        for recipient in recipients {
            let row = tableE2eUsers(account: account, ocIdServerUrl: rootID, userId: recipient.userId)
            row.certificate = recipient.certificate
            row.encryptedMetadataKey = recipient.encryptedMetadataKey
            row.metadataKey = recipient.metadataKey
            row.serverUrl = serverUrl
            row.authenticated = true
            realm.add(row, update: .all)
        }
    }

    /// Must be called within a Realm write transaction. Validation performs no writes;
    /// the counter is checked here again after acquiring Realm's writer lock.
    static func applyE2eeSnapshot(_ snapshot: E2eeValidatedSnapshot, in realm: Realm) throws {
        let counter = realm.object(ofType: tableE2eCounter.self, forPrimaryKey: snapshot.account + snapshot.ocIdServerUrl)
        try checkE2eeCounter(snapshot.counter, saved: counter?.counter)

        if let recipients = snapshot.recipients {
            replaceE2eeRecipients(recipients, account: snapshot.account, serverUrl: snapshot.serverUrl, rootID: snapshot.ocIdServerUrl, in: realm)
        }
        let metadata = tableE2eMetadata(account: snapshot.account, ocIdServerUrl: snapshot.ocIdServerUrl)
        metadata.keyChecksums.append(objectsIn: snapshot.keyChecksums)
        metadata.deleted = snapshot.deleted
        for (identifier, name) in snapshot.folders { metadata.folders[identifier] = name }
        metadata.serverUrl = snapshot.serverUrl
        metadata.version = snapshot.version
        realm.add(metadata, update: .all)

        reconcileE2eeFiles(snapshot.files, account: snapshot.account, serverUrl: snapshot.serverUrl,
                           ocIdServerUrl: snapshot.ocIdServerUrl, version: "2", authenticated: true, in: realm)
        realm.add(tableE2eCounter(account: snapshot.account, ocIdServerUrl: snapshot.ocIdServerUrl, counter: snapshot.counter, requiresV2: true), update: .all)
    }

    private static func reconcileE2eeFiles(_ files: [E2eeFile], account: String, serverUrl: String,
                                           ocIdServerUrl: String, version: String, authenticated: Bool, in realm: Realm) {
        // A remote snapshot is authoritative for remote records. Keep local work until
        // a matching authenticated server snapshot acknowledges it.
        let oldRows = realm.objects(tableE2eEncryption.self).filter("account == %@ AND serverUrl == %@ AND locallyGenerated == false", account, serverUrl)
        realm.delete(oldRows)
        for file in files {
            let primaryKey = account + ocIdServerUrl + file.identifier
            if let pending = realm.object(ofType: tableE2eEncryption.self, forPrimaryKey: primaryKey), pending.locallyGenerated {
                let sameFile = pending.fileName == file.name && pending.mimeType == file.mimeType
                    && (file.mimeType == "httpd/unix-directory" || (pending.key == file.key && pending.initializationVector == file.nonce && pending.authenticationTag == file.authenticationTag))
                if !sameFile { continue }
            }
            let row = tableE2eEncryption(account: account, ocIdServerUrl: ocIdServerUrl, fileNameIdentifier: file.identifier)
            row.authenticationTag = file.authenticationTag
            row.fileName = file.name
            row.key = file.key
            row.initializationVector = file.nonce
            row.metadataKey = file.metadataKey
            row.metadataKeyIndex = file.metadataKeyIndex
            row.mimeType = file.mimeType
            row.blob = file.blob
            row.serverUrl = serverUrl
            row.version = version
            row.authenticated = authenticated
            realm.add(row, update: .all)
            for item in realm.objects(tableMetadata.self).filter("account == %@ AND serverUrl == %@ AND fileName == %@", account, serverUrl, file.identifier) {
                item.fileNameView = file.name
                item.contentType = file.contentType
                item.iconName = file.iconName
                item.classFile = file.classFile
                item.typeIdentifier = file.typeIdentifier
            }
        }
    }

    static func applyLegacyE2eeSnapshot(_ snapshot: E2eeLegacySnapshot, in realm: Realm) throws {
        guard try !requiresE2eeV2(account: snapshot.account, serverUrl: snapshot.serverUrl, ocIdServerUrl: snapshot.ocIdServerUrl, in: realm) else {
            throw E2eeStateError.versionDowngrade
        }
        if let existing = realm.object(ofType: tableE2eMetadata12.self, forPrimaryKey: snapshot.serverUrl), existing.version > snapshot.version {
            throw E2eeStateError.versionDowngrade
        }
        reconcileE2eeFiles(snapshot.files, account: snapshot.account, serverUrl: snapshot.serverUrl,
                           ocIdServerUrl: snapshot.ocIdServerUrl, version: String(snapshot.version), authenticated: false, in: realm)
        let metadata = tableE2eMetadata12()
        metadata.account = snapshot.account
        metadata.serverUrl = snapshot.serverUrl
        metadata.metadataKey = snapshot.metadataKey
        metadata.version = snapshot.version
        realm.add(metadata, update: .all)
    }

    func commitLegacyE2eeSnapshot(_ snapshot: E2eeLegacySnapshot) async throws {
        try await core.performRealmTransactionAsync { realm in
            try Self.applyLegacyE2eeSnapshot(snapshot, in: realm)
        }
    }

    func commitE2eeSnapshot(_ snapshot: E2eeValidatedSnapshot) async throws {
        try await core.performRealmTransactionAsync { realm in
            try Self.applyE2eeSnapshot(snapshot, in: realm)
        }
    }

    func replaceE2eeRecipientsAsync(_ recipients: [E2eeRecipient], account: String, serverUrl: String, rootID: String) async throws {
        try await core.performRealmTransactionAsync { realm in
            Self.replaceE2eeRecipients(recipients, account: account, serverUrl: serverUrl, rootID: rootID, in: realm)
        }
    }

    func deleteE2EUsersAsync(account: String, ocIdServerUrl: String, userId: String) async {
        await core.performRealmWriteAsync { realm in
            if let result = realm.objects(tableE2eUsers.self)
                .filter("account == %@ AND ocIdServerUrl == %@ AND userId == %@", account, ocIdServerUrl, userId)
                .first {
                realm.delete(result)
            }
        }
    }

    func getE2EUsersAsync(account: String, directoryTopOcId: String) async -> [tableE2eUsers] {
        await core.performRealmReadAsync { realm in
            realm.objects(tableE2eUsers.self)
                .filter("account == %@ AND ocIdServerUrl == %@", account, directoryTopOcId)
                .map { tableE2eUsers(value: $0) } // detached copy
        } ?? []
    }

    func getE2EUserAsync(account: String, directoryTopOcId: String, userId: String) async -> tableE2eUsers? {
        await core.performRealmReadAsync { realm in
            realm.objects(tableE2eUsers.self)
                .filter("account == %@ AND ocIdServerUrl == %@ AND userId == %@", account, directoryTopOcId, userId)
                .first
                .map { tableE2eUsers(value: $0) } // detached copy
        }
    }

    func getE2eMetadataAsync(account: String, ocIdServerUrl: String) async -> tableE2eMetadata? {
        await core.performRealmReadAsync { realm in
            realm.objects(tableE2eMetadata.self)
                .filter("account == %@ AND ocIdServerUrl == %@", account, ocIdServerUrl)
                .first
                .map { tableE2eMetadata(value: $0) } // detached copy
        }
    }

    func addE2eMetadataAsync(account: String,
                             serverUrl: String,
                             ocIdServerUrl: String,
                             keyChecksums: [String]?,
                             deleted: Bool,
                             folders: [String: String]?,
                             version: String) async {
        await core.performRealmWriteAsync { realm in
            let object = tableE2eMetadata(account: account, ocIdServerUrl: ocIdServerUrl)

            if let keyChecksums {
                object.keyChecksums.append(objectsIn: keyChecksums)
            }

            object.deleted = deleted

            if let folders {
                for (key, value) in folders {
                    object.folders[key] = value
                }
            }

            object.serverUrl = serverUrl
            object.version = version

            realm.add(object, update: .all)
        }
    }

    func initializeE2eeCounterAsync(account: String, ocIdServerUrl: String, requiresV2: Bool) async throws {
        try await core.performRealmTransactionAsync { realm in
            let existing = realm.object(ofType: tableE2eCounter.self, forPrimaryKey: account + ocIdServerUrl)
            let counter = existing?.counter ?? 0
            realm.add(tableE2eCounter(account: account, ocIdServerUrl: ocIdServerUrl, counter: counter,
                                      requiresV2: requiresV2 || (existing?.requiresV2 ?? false) || counter > 0), update: .all)
        }
    }

    func updateCounterE2eMetadataAsync(account: String, ocIdServerUrl: String, counter: Int, requiresV2: Bool = false) async {
        await core.performRealmWriteAsync { realm in
            guard counter >= 0 else { return }
            let existing = realm.object(ofType: tableE2eCounter.self, forPrimaryKey: account + ocIdServerUrl)
            guard counter >= (existing?.counter ?? 0) else { return }
            let object = tableE2eCounter(account: account, ocIdServerUrl: ocIdServerUrl, counter: counter,
                                         requiresV2: requiresV2 || (existing?.requiresV2 ?? false) || counter > 0)
            realm.add(object, update: .all)
        }
    }

    func getCounterE2eMetadataAsync(account: String, ocIdServerUrl: String) async -> Int? {
        await core.performRealmReadAsync { realm in
            realm.objects(tableE2eCounter.self)
                .filter("account == %@ AND ocIdServerUrl == %@", account, ocIdServerUrl)
                .first?
                .counter
        }
    }
}
