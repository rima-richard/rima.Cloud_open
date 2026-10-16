// SPDX-FileCopyrightText: Nextcloud GmbH
// SPDX-FileCopyrightText: 2017 Marino Faggiana
// SPDX-License-Identifier: GPL-3.0-or-later

import UIKit
import NextcloudKit

class NCEndToEndMetadata: NSObject {
    let utilityFileSystem = NCUtilityFileSystem()
    let database = NCManageDatabase.shared

    enum MetadataFormat: Equatable {
        case legacyV1, legacyV12, v2
    }

    /// Codable ignores unknown fields, so classify the envelope before decoding any
    /// version. Mixed legacy/V2 forms must never select an unsigned decoder.
    static func metadataFormat(_ data: Data, requiresV2: Bool) throws -> MetadataFormat {
        guard let envelope = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let metadata = envelope["metadata"] as? [String: Any] else { throw NKError.invalidData }
        let v1 = metadata["metadataKeys"] != nil
        let v12 = metadata["metadataKey"] != nil
        let v2 = envelope["version"] != nil || envelope["users"] != nil
            || metadata["ciphertext"] != nil || metadata["nonce"] != nil || metadata["authenticationTag"] != nil
        guard [v1, v12, v2].filter({ $0 }).count == 1 else { throw NKError.invalidData }
        if v2 {
            guard envelope["files"] == nil, metadata["version"] == nil else { throw NKError.invalidData }
            let decoded = try JSONDecoder().decode(E2eeV2.self, from: data)
            guard decoded.version == "2" || decoded.version.hasPrefix("2.") else { throw NKError.invalidData }
            return .v2
        }
        guard !requiresV2 else { throw NCManageDatabase.E2eeStateError.versionDowngrade }
        if v1 {
            let decoded = try JSONDecoder().decode(E2eeV1.self, from: data)
            guard decoded.metadata.version >= 1, decoded.metadata.version < 2 else { throw NKError.invalidData }
            return .legacyV1
        }
        let decoded = try JSONDecoder().decode(E2eeV12.self, from: data)
        guard decoded.metadata.version >= 1, decoded.metadata.version < 2 else { throw NKError.invalidData }
        return .legacyV12
    }

    static func encodingFormat(version: String, requiresV2: Bool) throws -> MetadataFormat {
        if version == "2" || version.hasPrefix("2.") { return .v2 }
        guard version.hasPrefix("1."), !requiresV2 else { throw NCManageDatabase.E2eeStateError.versionDowngrade }
        return .legacyV12
    }

    // --------------------------------------------------------------------------------------------
    // MARK: Encode JSON Metadata Bridge
    // --------------------------------------------------------------------------------------------

    func encodeMetadata(serverUrl: String, addUserId: String? = nil, addCertificate: String? = nil, removeUserId: String? = nil, session: NCSession.Session) async -> (metadata: String?, signature: String?, counter: Int, error: NKError) {

        guard let directory = self.database.getTableDirectory(predicate: NSPredicate(format: "account == %@ AND serverUrl == %@", session.account, serverUrl)) else {
            return (nil, nil, 0, NKError(errorCode: NCGlobal.shared.errorUnexpectedResponseFromDB,
                                         errorDescription: NSLocalizedString("_e2ee_no_session_", comment: "")))
        }
        let capabilities = await NKCapabilities.shared.getCapabilities(for: session.account)

        do {
            let requiresV2 = try await database.requiresE2eeV2Async(account: session.account, serverUrl: serverUrl, ocIdServerUrl: directory.ocId)
            switch try Self.encodingFormat(version: capabilities.e2EEApiVersion, requiresV2: requiresV2) {
            case .legacyV1, .legacyV12:
                return await encodeMetadataV1(account: session.account, serverUrl: serverUrl, ocIdServerUrl: directory.ocId)
            case .v2:
                return await encodeMetadataV2(serverUrl: serverUrl, ocIdServerUrl: directory.ocId, addUserId: addUserId, addCertificate: addCertificate, removeUserId: removeUserId, session: session)
            }
        } catch {
            return (nil, nil, 0, NKError(errorCode: NCGlobal.shared.errorE2EEVersion, errorDescription: "An encrypted folder cannot downgrade its metadata version."))
        }
    }

    // --------------------------------------------------------------------------------------------
    // MARK: Decode JSON Metadata Bridge
    // --------------------------------------------------------------------------------------------

    func decodeMetadata(
        _ metadata: String,
        signature: String?,
        serverUrl: String,
        session: NCSession.Session
    ) async -> (error: NKError, access: NCEndToEndKeySetAccess) {
        guard let data = metadata.data(using: .utf8), let directory = self.database.getTableDirectory(predicate: NSPredicate(format: "account == %@ AND serverUrl == %@", session.account, serverUrl)) else {
            return (
                NKError(errorCode: NCGlobal.shared.errorE2EEJSon, errorDescription: "Unable to decode the metadata file"),
                .unavailable
            )
        }

        let format: MetadataFormat
        do {
            let requiresV2 = try await database.requiresE2eeV2Async(account: session.account, serverUrl: serverUrl, ocIdServerUrl: directory.ocId)
            format = try Self.metadataFormat(data, requiresV2: requiresV2)
        } catch {
            return (NKError(errorCode: NCGlobal.shared.errorE2EEVersion, errorDescription: "Invalid or downgraded encrypted metadata."), .unavailable)
        }

        let access: NCEndToEndKeySetAccess
        do {
            access = try await resolveKeySetAccess(metadata, serverUrl: serverUrl, session: session)
        } catch {
            nkLog(
                tag: NCGlobal.shared.logTagE2EE,
                message: "Unable to resolve E2EE key-set access."
            )
            return (
                NKError(errorCode: NCGlobal.shared.errorInternalError, errorDescription: error.localizedDescription),
                .unavailable
            )
        }

        nkLog(
            tag: NCGlobal.shared.logTagE2EE,
            message: "Resolved E2EE key-set access: \(access.diagnosticDescription)."
        )

        guard let keySet = access.keySet else {
            return (
                NKError(
                    errorCode: NCGlobal.shared.errorE2EENoUserFound,
                    errorDescription: NSLocalizedString("_e2ee_no_metadataKey_found_", comment: "")
                ),
                .unavailable
            )
        }

        let error: NKError
        if format == .legacyV1 {
            error = await decodeMetadataV1(
                metadata,
                serverUrl: serverUrl,
                ocIdServerUrl: directory.ocId,
                session: session,
                keySet: keySet
            )
        } else if format == .legacyV12 {
            error = await decodeMetadataV12(
                metadata,
                serverUrl: serverUrl,
                ocIdServerUrl: directory.ocId,
                session: session,
                keySet: keySet
            )
        } else {
            error = await decodeMetadataV2(
                metadata,
                signature: signature,
                serverUrl: serverUrl,
                ocIdServerUrl: directory.ocId,
                session: session,
                keySet: keySet
            )
        }

        return (error, access)
    }

    func resolveKeySetAccess(
        _ metadata: String,
        serverUrl: String,
        session: NCSession.Session
    ) async throws -> NCEndToEndKeySetAccess {
        guard let data = metadata.data(using: .utf8),
              let directory = await database.getTableDirectoryAsync(predicate: NSPredicate(format: "account == %@ AND serverUrl == %@", session.account, serverUrl)) else { throw NKError.invalidData }
        let requiresV2 = try await database.requiresE2eeV2Async(account: session.account, serverUrl: serverUrl, ocIdServerUrl: directory.ocId)
        _ = try Self.metadataFormat(data, requiresV2: requiresV2)
        var childRootEncryptedMetadataKey: String?
        if let data = metadata.data(using: .utf8),
           let metadataV2 = try? JSONDecoder().decode(E2eeV2.self, from: data),
           metadataV2.users?.isEmpty != false,
           let directoryTop = await utilityFileSystem.getMetadataE2EETopAsync(
               serverUrl: serverUrl,
               session: session
           ),
           serverUrl != directoryTop.serverUrlFileName {
            childRootEncryptedMetadataKey = try await storedRootEncryptedMetadataKey(
                serverUrl: serverUrl,
                session: session
            )
        }

        return try NCEndToEndKeySetResolver().resolve(
            metadata: metadata,
            account: session.account,
            userId: session.userId,
            rootEncryptedMetadataKey: childRootEncryptedMetadataKey
        )
    }

    func resolveStoredRootKeySetAccess(
        serverUrl: String,
        session: NCSession.Session
    ) async throws -> NCEndToEndKeySetAccess {
        guard let encryptedMetadataKey = try await storedRootEncryptedMetadataKey(
            serverUrl: serverUrl,
            session: session
        ) else {
            return .unavailable
        }

        return try NCEndToEndKeySetResolver().resolve(
            encryptedMetadataKey: encryptedMetadataKey,
            account: session.account
        )
    }

    private func storedRootEncryptedMetadataKey(
        serverUrl: String,
        session: NCSession.Session
    ) async throws -> String? {
        guard let directoryTop = await utilityFileSystem.getMetadataE2EETopAsync(
            serverUrl: serverUrl,
            session: session
        ),
        let tableUser = await database.getE2EUserAsync(
            account: session.account,
            directoryTopOcId: directoryTop.ocId,
            userId: session.userId
        ), tableUser.authenticated else {
            return nil
        }

        return tableUser.encryptedMetadataKey
    }
}
