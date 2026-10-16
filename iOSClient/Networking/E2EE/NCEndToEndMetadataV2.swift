// SPDX-FileCopyrightText: Nextcloud GmbH
// SPDX-FileCopyrightText: 2023 Marino Faggiana
// SPDX-License-Identifier: GPL-3.0-or-later

import Foundation
import UIKit
import NextcloudKit
import Gzip

extension NCEndToEndMetadata {
    struct E2eeV2: Codable {

        struct Metadata: Codable {
            let ciphertext: String
            let nonce: String
            let authenticationTag: String

            struct ciphertext: Codable {
                let counter: Int
                let deleted: Bool?
                let keyChecksums: [String]?
                let files: [String: Files]?
                let folders: [String: String]?

                struct Files: Codable {
                    let authenticationTag: String
                    let filename: String
                    let key: String
                    let mimetype: String
                    let nonce: String
                }
            }
        }

        struct Users: Codable {
            let userId: String
            let certificate: String
            let encryptedMetadataKey: String?
        }

        struct Filedrop: Codable {
            let ciphertext: String
            let nonce: String
            let authenticationTag: String
            let users: [UsersFiledrop]

            struct UsersFiledrop: Codable {
                let userId: String
                let encryptedFiledropKey: String
            }
        }

        let metadata: Metadata
        let users: [Users]?
        let filedrop: [String: Filedrop]?
        let version: String
    }

    struct E2eeV2Signature: Codable {

        struct Metadata: Codable {
            let ciphertext: String
            let nonce: String
            let authenticationTag: String
        }

        struct Users: Codable {
            let userId: String
            let certificate: String
            let encryptedMetadataKey: String?
        }

        let metadata: Metadata
        let users: [Users]?
        let version: String
    }

    // --------------------------------------------------------------------------------------------
    // MARK: Encode JSON Metadata V2
    // --------------------------------------------------------------------------------------------

    func encodeMetadataV2(serverUrl: String, ocIdServerUrl: String, addUserId: String?, addCertificate: String?, removeUserId: String?, session: NCSession.Session) async -> (metadata: String?, signature: String?, counter: Int, error: NKError) {
        guard let directoryTop = await utilityFileSystem.getMetadataE2EETopAsync(serverUrl: serverUrl, session: session) else {
            return (nil, nil, 0, NKError(errorCode: NCGlobal.shared.errorE2EEKeyDirectoryTop,
                                         errorDescription: NSLocalizedString("_e2ee_no_dir_", comment: "")))
        }
        guard let certificate = NCPreferences().getEndToEndCertificate(account: session.account) else {
            return (nil, nil, 0, NKError(errorCode: NCGlobal.shared.errorUnexpectedResponseFromDB,
                                         errorDescription: NSLocalizedString("_e2ee_no_certificate_", comment: "")))
        }

        let capabilities = await NKCapabilities.shared.getCapabilities(for: session.account)
        guard (try? Self.encodingFormat(version: capabilities.e2EEApiVersion, requiresV2: true)) == .v2 else {
            return (nil, nil, 0, .invalidData)
        }
        let isDirectoryTop = serverUrl == directoryTop.serverUrlFileName
        let directoryTopOcId = directoryTop.ocId

        let cachedUsers = await database.getE2EUsersAsync(account: session.account, directoryTopOcId: directoryTopOcId)
        let authenticatedUsers = cachedUsers.filter { $0.authenticated }
        let savedCounter = await database.getCounterE2eMetadataAsync(account: session.account, ocIdServerUrl: ocIdServerUrl)
        guard let counter = Self.nextMetadataCounter(savedCounter) else {
            return (nil, nil, 0, NKError(errorCode: NCGlobal.shared.errorE2EEKeyChecksums,
                                       errorDescription: NSLocalizedString("_e2ee_counter_check_", comment: "")))
        }
        let key: Data
        if let savedKey = authenticatedUsers.first(where: { $0.userId == session.userId })?.metadataKey {
            key = savedKey
        } else if isDirectoryTop, cachedUsers.isEmpty, (savedCounter ?? 0) == 0,
                  let generatedKey = NCEndToEndEncryption.shared().generateKey() {
            // A newly marked root is explicitly initialized with counter zero.
            key = generatedKey
        } else {
            return (nil, nil, 0, NKError(errorCode: NCGlobal.shared.errorE2EENoUserFound,
                                       errorDescription: NSLocalizedString("_e2ee_no_metadataKey_found_", comment: "")))
        }
        let metadataKey = key.base64EncodedString()
        guard let checksum = NCEndToEndEncryption.shared().createSHA256(key) else {
            return (nil, nil, 0, .invalidData)
        }
        let keyChecksums = [checksum]
        var recipients: [NCManageDatabase.E2eeRecipient] = []
        var usersCodable: [E2eeV2.Users] = []
        var filesCodable: [String: E2eeV2.Metadata.ciphertext.Files] = [:]
        var folders: [String: String] = [:]

        if isDirectoryTop {
            do {
                recipients = try prepareRecipientsV2(cachedUsers: cachedUsers, key: key, userId: session.userId, certificate: certificate, addUserId: addUserId, addCertificate: addCertificate, removeUserId: removeUserId)
                usersCodable = recipients.map {
                    .init(userId: $0.userId, certificate: $0.certificate, encryptedMetadataKey: $0.encryptedMetadataKey)
                }
            } catch {
                return (nil, nil, counter, .invalidData)
            }
        }

        // CIPERTEXT
        //
        guard let e2eEncryptions = try? await database.getE2eEncryptionsThrowingAsync(predicate: NSPredicate(format: "account == %@ AND serverUrl == %@", session.account, serverUrl)),
              let usableEncryptions = try? Self.outgoingEncryptionRowsV2(e2eEncryptions) else {
            return (nil, nil, counter, .invalidData)
        }
        for e2eEncryption in usableEncryptions {
            if e2eEncryption.mimeType == "httpd/unix-directory" {
                folders[e2eEncryption.fileNameIdentifier] = e2eEncryption.fileName
            } else {
                let file = E2eeV2.Metadata.ciphertext.Files(authenticationTag: e2eEncryption.authenticationTag, filename: e2eEncryption.fileName, key: e2eEncryption.key, mimetype: e2eEncryption.mimeType, nonce: e2eEncryption.initializationVector)
                filesCodable.updateValue(file, forKey: e2eEncryption.fileNameIdentifier)
            }
        }

        do {
            var authenticationTag: NSString?
            var initializationVector: NSString?
            let json = try JSONEncoder().encode(E2eeV2.Metadata.ciphertext(counter: counter, deleted: false, keyChecksums: keyChecksums, files: filesCodable, folders: folders))
            let jsonZip = try json.gzipped()
            let ciphertextMetadata = NCEndToEndEncryption.shared().encryptPayloadFile(jsonZip, key: metadataKey, initializationVector: &initializationVector, authenticationTag: &authenticationTag)
            guard var ciphertextMetadata, let initializationVector = initializationVector as? String, let authenticationTag = authenticationTag as? String else {
                return (nil, nil, counter, NKError(errorCode: NCGlobal.shared.errorE2EEEncryptPayloadFile,
                                                   errorDescription: NSLocalizedString("_e2ee_enc_payload_", comment: "")))
            }

            // Add initializationVector [ANDROID]
            ciphertextMetadata = ciphertextMetadata + "|" + initializationVector

            let metadataCodable = E2eeV2.Metadata(ciphertext: ciphertextMetadata, nonce: initializationVector, authenticationTag: authenticationTag)
            let e2eeCodable = E2eeV2(metadata: metadataCodable, users: usersCodable, filedrop: nil, version: capabilities.e2EEApiVersion)
            let e2eeData = try JSONEncoder().encode(e2eeCodable)

            let e2eeJson = String(data: e2eeData, encoding: .utf8)
            guard let signature = createSignature(metadata: metadataCodable, users: usersCodable, version: capabilities.e2EEApiVersion, certificate: certificate, session: session) else {
                return (nil, nil, counter, NKError(errorCode: NCGlobal.shared.errorE2EEKeyVerifySignature,
                                                 errorDescription: NSLocalizedString("_e2ee_signature_failed_", comment: "")))
            }
            if isDirectoryTop {
                try await database.replaceE2eeRecipientsAsync(recipients, account: session.account, serverUrl: serverUrl, rootID: directoryTopOcId)
            }
            return (e2eeJson, signature, counter, NKError())

        } catch let error {
            return (nil, nil, counter, NKError(errorCode: NCGlobal.shared.errorE2EEJSon, errorDescription: error.localizedDescription))
        }
    }

    // --------------------------------------------------------------------------------------------
    // MARK: Decode JSON Metadata V2
    // --------------------------------------------------------------------------------------------

    static func outgoingEncryptionRowsV2(_ rows: [tableE2eEncryption]) throws -> [tableE2eEncryption] {
        guard rows.allSatisfy({ $0.isUsableForE2eeV2 }) else { throw NKError.invalidData }
        return rows
    }

    func prepareRecipientsV2(cachedUsers: [tableE2eUsers], key: Data, userId: String, certificate: String,
                             addUserId: String?, addCertificate: String?, removeUserId: String?) throws -> [NCManageDatabase.E2eeRecipient] {
        // Only authenticated root participants and an explicit local share selection
        // may receive a newly wrapped metadata key.
        var certificates: [String: String] = [:]
        for user in cachedUsers where user.authenticated { certificates[user.userId] = user.certificate }
        certificates[userId] = certificate
        if let addUserId {
            guard let addCertificate, !addCertificate.isEmpty else { throw NKError.invalidData }
            certificates[addUserId] = addCertificate
        }
        if let removeUserId { certificates.removeValue(forKey: removeUserId) }
        return try certificates.sorted(by: { $0.key < $1.key }).map { recipientID, recipientCertificate in
            guard let encrypted = NCEndToEndEncryption.shared().encryptAsymmetricData(key, certificate: recipientCertificate) else {
                throw NKError.invalidData
            }
            return .init(userId: recipientID, certificate: recipientCertificate, encryptedMetadataKey: encrypted.base64EncodedString(), metadataKey: recipientID == userId ? key : nil)
        }
    }

    static func nextMetadataCounter(_ saved: Int?) -> Int? {
        let value = saved ?? 0
        guard value >= 0, value < Int.max else { return nil }
        return value + 1
    }

    struct PreparedMetadataV2 {
        var snapshot: NCManageDatabase.E2eeValidatedSnapshot
        let signerToConfirm: E2eeV2.Users?
    }

    /// Parse, authenticate and decrypt exclusively into values. Nothing is persisted
    /// until this returns and any previously unknown signer is explicitly confirmed.
    func prepareMetadataV2(_ jsonString: String,
                           signature: String?,
                           account: String,
                           userId: String,
                           serverUrl: String,
                           ocIdServerUrl: String,
                           isDirectoryTop: Bool,
                           keySet: NCEndToEndKeySet,
                           cachedUsers: [tableE2eUsers],
                           trustedCertificates: [String],
                           savedCounter: Int?) throws -> PreparedMetadataV2 {
        let global = NCGlobal.shared
        guard let signature, !signature.isEmpty else {
            throw NKError(errorCode: global.errorE2EEKeyVerifySignatureEmpty,
                          errorDescription: NSLocalizedString("_e2ee_no_signature_found_", comment: ""))
        }
        guard let data = jsonString.data(using: .utf8) else { throw NKError.invalidData }
        guard try Self.metadataFormat(data, requiresV2: true) == .v2 else { throw NKError.invalidData }
        let json = try JSONDecoder().decode(E2eeV2.self, from: data)
        let users = json.users ?? []
        guard Set(users.map { $0.userId }).count == users.count else { throw NKError.invalidData }
        let authenticatedUsers = cachedUsers.filter { $0.authenticated }
        let certificates = [keySet.certificate].compactMap { $0 } + trustedCertificates + authenticatedUsers.map { $0.certificate }
        let knownSigner = verifySignature(signature: signature, metadata: json.metadata, users: json.users, version: json.version, certificates: certificates)
        var signerToConfirm: E2eeV2.Users?
        if !knownSigner {
            // An incoming certificate is only a candidate for a fingerprint prompt,
            // never a trust anchor. Verify each candidate separately to identify the signer.
            signerToConfirm = isDirectoryTop ? users.first { user in
                verifySignature(signature: signature, metadata: json.metadata, users: json.users, version: json.version, certificates: [user.certificate])
            } : nil
            guard signerToConfirm != nil else {
                throw NKError(errorCode: global.errorE2EEKeyVerifySignature,
                              errorDescription: NSLocalizedString("_e2ee_signature_failed_", comment: ""))
            }
        }

        let key: Data
        if isDirectoryTop {
            guard let user = users.first(where: { $0.userId == userId }),
                  let encodedKey = user.encryptedMetadataKey,
                  let encryptedKey = Data(base64Encoded: encodedKey),
                  let decrypted = NCEndToEndEncryption.shared().decryptAsymmetricData(encryptedKey, privateKey: keySet.privateKey) else {
                throw NKError(errorCode: global.errorE2EENoUserFound,
                              errorDescription: NSLocalizedString("_e2ee_no_metadataKey_found_", comment: ""))
            }
            key = decrypted
        } else {
            guard let decrypted = authenticatedUsers.first(where: { $0.userId == userId })?.metadataKey else {
                throw NKError(errorCode: global.errorE2EENoUserFound,
                              errorDescription: NSLocalizedString("_e2ee_no_metadataKey_found_", comment: ""))
            }
            key = decrypted
        }
        let metadataKey = key.base64EncodedString()
        let metadata = json.metadata
        guard let decryptedMetadata = NCEndToEndEncryption.shared().decryptPayloadFile(metadata.ciphertext, key: metadataKey, initializationVector: metadata.nonce, authenticationTag: metadata.authenticationTag),
              decryptedMetadata.isGzipped else {
            throw NKError(errorCode: global.errorE2EEKeyCiphertext,
                          errorDescription: NSLocalizedString("_e2ee_key_ciphertext_", comment: ""))
        }
        let payload = try JSONDecoder().decode(E2eeV2.Metadata.ciphertext.self, from: decryptedMetadata.gunzipped())
        guard let checksums = payload.keyChecksums, !checksums.isEmpty else {
            throw NKError(errorCode: global.errorE2EEKeyChecksumsEmpty,
                          errorDescription: NSLocalizedString("_e2ee_key_no_checksum_found_", comment: ""))
        }
        guard let hash = NCEndToEndEncryption.shared().createSHA256(key), checksums.contains(hash) else {
            throw NKError(errorCode: global.errorE2EEKeyChecksums,
                          errorDescription: NSLocalizedString("_e2ee_key_checksum_", comment: ""))
        }
        try NCManageDatabase.checkE2eeCounter(payload.counter, saved: savedCounter)

        var files: [NCManageDatabase.E2eeFile] = []
        // Filedrop entries are not part of the CMS envelope. Their own authenticated
        // decryption must succeed, and their effects are staged with the signed metadata.
        for (identifier, filedrop) in json.filedrop ?? [:] {
            let recipients = filedrop.users.filter { $0.userId == userId }
            guard recipients.count <= 1 else { throw NKError.invalidData }
            guard let recipient = recipients.first else { continue }
            guard let encryptedKey = Data(base64Encoded: recipient.encryptedFiledropKey),
                  let decryptedKey = NCEndToEndEncryption.shared().decryptAsymmetricData(encryptedKey, privateKey: keySet.privateKey),
                  let decrypted = NCEndToEndEncryption.shared().decryptPayloadFile(filedrop.ciphertext, key: decryptedKey.base64EncodedString(), initializationVector: filedrop.nonce, authenticationTag: filedrop.authenticationTag),
                  decrypted.isGzipped else {
                throw NKError(errorCode: global.errorE2EEKeyFiledropCiphertext,
                              errorDescription: NSLocalizedString("_e2ee_filedrop_ciphertext_", comment: ""))
            }
            let file = try JSONDecoder().decode(E2eeV2.Metadata.ciphertext.Files.self, from: decrypted.gunzipped())
            files.append(.init(identifier: identifier, name: file.filename, authenticationTag: file.authenticationTag, key: file.key, nonce: file.nonce, metadataKey: decryptedKey.base64EncodedString(), mimeType: file.mimetype))
        }
        for (identifier, file) in payload.files ?? [:] {
            files.append(.init(identifier: identifier, name: file.filename, authenticationTag: file.authenticationTag, key: file.key, nonce: file.nonce, metadataKey: metadataKey, mimeType: file.mimetype))
        }
        for (identifier, name) in payload.folders ?? [:] {
            files.append(.init(identifier: identifier, name: name, authenticationTag: metadata.authenticationTag, key: metadataKey, nonce: metadata.nonce, metadataKey: metadataKey, mimeType: "httpd/unix-directory"))
        }
        for file in files {
            _ = try NCUtilityFileSystem.validatedFileName(file.identifier)
            _ = try NCUtilityFileSystem.validatedFileName(file.name)
        }
        let recipients: [NCManageDatabase.E2eeRecipient]? = isDirectoryTop ? users.map {
            .init(userId: $0.userId, certificate: $0.certificate, encryptedMetadataKey: $0.encryptedMetadataKey, metadataKey: $0.userId == userId ? key : nil)
        } : nil
        let snapshot = NCManageDatabase.E2eeValidatedSnapshot(account: account, serverUrl: serverUrl, ocIdServerUrl: ocIdServerUrl, counter: payload.counter, recipients: recipients, keyChecksums: checksums, deleted: payload.deleted ?? false, folders: payload.folders ?? [:], version: json.version, files: files)
        return PreparedMetadataV2(snapshot: snapshot, signerToConfirm: signerToConfirm)
    }

    func decodeMetadataV2(_ json: String,
                          signature: String?,
                          serverUrl: String,
                          ocIdServerUrl: String,
                          session: NCSession.Session,
                          keySet: NCEndToEndKeySet) async -> NKError {
        guard let directoryTop = await utilityFileSystem.getMetadataE2EETopAsync(serverUrl: serverUrl, session: session) else {
            return NKError(errorCode: NCGlobal.shared.errorE2EEKeyDirectoryTop,
                           errorDescription: NSLocalizedString("_e2ee_no_metadata_", comment: ""))
        }
        do {
            let rootID = directoryTop.ocId
            let cachedUsers = await database.getE2EUsersAsync(account: session.account, directoryTopOcId: rootID)
            let savedCounter = await database.getCounterE2eMetadataAsync(account: session.account, ocIdServerUrl: ocIdServerUrl)
            var prepared = try prepareMetadataV2(json, signature: signature, account: session.account, userId: session.userId, serverUrl: serverUrl, ocIdServerUrl: ocIdServerUrl, isDirectoryTop: serverUrl == directoryTop.serverUrlFileName, keySet: keySet, cachedUsers: cachedUsers, trustedCertificates: NCEndToEndSignerTrust.certificates(account: session.account, rootID: rootID), savedCounter: savedCounter)
            for index in prepared.snapshot.files.indices {
                let file = prepared.snapshot.files[index]
                let type = await NKTypeIdentifiers.shared.getInternalType(fileName: file.name, mimeType: file.mimeType, directory: file.mimeType == "httpd/unix-directory", account: session.account)
                prepared.snapshot.files[index].contentType = type.mimeType
                prepared.snapshot.files[index].iconName = type.iconName
                prepared.snapshot.files[index].classFile = type.classFile
                prepared.snapshot.files[index].typeIdentifier = type.typeIdentifier
            }
            if let signer = prepared.signerToConfirm {
                // No prompt is shown for malformed, undecryptable or already stale data.
                guard await NCEndToEndSignerTrust.confirm(account: session.account, rootID: rootID, claimedUserID: signer.userId, certificate: signer.certificate),
                      let signature, let data = json.data(using: .utf8) else {
                    return NKError(errorCode: NCGlobal.shared.errorE2EEKeyVerifySignature,
                                   errorDescription: NSLocalizedString("_e2ee_signature_failed_", comment: ""))
                }
                let envelope = try JSONDecoder().decode(E2eeV2.self, from: data)
                guard verifySignature(signature: signature, metadata: envelope.metadata, users: envelope.users, version: envelope.version, certificates: [signer.certificate]) else {
                    return NKError(errorCode: NCGlobal.shared.errorE2EEKeyVerifySignature,
                                   errorDescription: NSLocalizedString("_e2ee_signature_failed_", comment: ""))
                }
            }
            try await database.commitE2eeSnapshot(prepared.snapshot)
            return NKError()
        } catch NCManageDatabase.E2eeStateError.staleCounter {
            return NKError(errorCode: NCGlobal.shared.errorE2EEKeyChecksums,
                           errorDescription: NSLocalizedString("_e2ee_counter_check_", comment: ""))
        } catch let error as NKError {
            return error
        } catch {
            return NKError(errorCode: NCGlobal.shared.errorE2EEJSon, errorDescription: error.localizedDescription)
        }
    }

    // MARK: -

    func createSignature(metadata: E2eeV2.Metadata, users: [E2eeV2.Users]?, version: String, certificate: String, session: NCSession.Session) -> String? {
        guard let users else { return nil }
        var usersSignatureCodable: [E2eeV2Signature.Users] = []

        for user in users {
            usersSignatureCodable.append(E2eeV2Signature.Users(userId: user.userId, certificate: user.certificate, encryptedMetadataKey: user.encryptedMetadataKey))
        }

        let signatureCodable = E2eeV2Signature(metadata: E2eeV2Signature.Metadata(ciphertext: metadata.ciphertext, nonce: metadata.nonce, authenticationTag: metadata.authenticationTag), users: usersSignatureCodable, version: version)

        do {
            let jsonEncoder = JSONEncoder()
            let json = try jsonEncoder.encode(signatureCodable)
            let dataSerialization = try JSONSerialization.jsonObject(with: json, options: [])
            let decoded = try JSONSerialization.data(withJSONObject: dataSerialization, options: [.sortedKeys, .withoutEscapingSlashes])
            let base64 = decoded.base64EncodedString()
            if let base64Data = base64.data(using: .utf8),
               let signatureData = NCEndToEndEncryption.shared().generateSignatureCMS(base64Data, certificate: certificate, privateKey: NCPreferences().getEndToEndPrivateKey(account: session.account), userId: session.userId) {
                return signatureData.base64EncodedString()
            }
        } catch {
            nkLog(tag: NCGlobal.shared.logTagE2EE, message: "Unable to create the E2EE metadata signature.")
        }

        return nil
    }

    func verifySignature(signature: String, metadata: E2eeV2.Metadata, users: [E2eeV2.Users]?, version: String, certificates: [String]) -> Bool {
        guard !certificates.isEmpty else { return false }
        let signatureUsers = users?.map {
            E2eeV2Signature.Users(userId: $0.userId, certificate: $0.certificate, encryptedMetadataKey: $0.encryptedMetadataKey)
        }
        let signatureCodable = E2eeV2Signature(metadata: E2eeV2Signature.Metadata(ciphertext: metadata.ciphertext, nonce: metadata.nonce, authenticationTag: metadata.authenticationTag), users: signatureUsers, version: version)

        do {
            let jsonEncoder = JSONEncoder()
            let json = try jsonEncoder.encode(signatureCodable)
            let dataSerialization = try JSONSerialization.jsonObject(with: json, options: [])
            if var dataSerialization = dataSerialization as? [String: Any?] {
                dataSerialization = dataSerialization.compactMapValues { $0 }
                let decodedSignatureCodable = try JSONSerialization.data(withJSONObject: dataSerialization, options: [.sortedKeys, .withoutEscapingSlashes])
                let base64 = decodedSignatureCodable.base64EncodedString()
                if let data = base64.data(using: .utf8), let signatureData = Data(base64Encoded: signature) {
                    return NCEndToEndEncryption.shared().verifySignatureCMS(signatureData, data: data, certificates: certificates)
                }
            }

        } catch {
            nkLog(tag: NCGlobal.shared.logTagE2EE, message: "Unable to verify the E2EE metadata signature.")
        }

        return false
    }

    @MainActor
    func showAlert(from viewController: UIViewController?,
                   title: String,
                   message: String,
                   cancelAction: String,
                   continueAction: String) async -> Bool {
        await withCheckedContinuation { continuation in
            let alertController = UIAlertController(
                title: NSLocalizedString(title, comment: ""),
                message: NSLocalizedString(message, comment: ""),
                preferredStyle: .alert
            )

            alertController.addAction(
                UIAlertAction(
                    title: NSLocalizedString(cancelAction, comment: ""),
                    style: .cancel
                ) { _ in
                    continuation.resume(returning: false)
                }
            )

            alertController.addAction(
                UIAlertAction(
                    title: NSLocalizedString(continueAction, comment: ""),
                    style: .destructive
                ) { _ in
                    continuation.resume(returning: true)
                }
            )

            viewController?.present(alertController, animated: true)
        }
    }
}
