// SPDX-FileCopyrightText: Nextcloud GmbH
// SPDX-FileCopyrightText: 2023 Marino Faggiana
// SPDX-License-Identifier: GPL-3.0-or-later

import Foundation
import UIKit
import NextcloudKit

extension NCEndToEndMetadata {

    struct E2eeV1: Codable {

        struct Metadata: Codable {
            let metadataKeys: [String: String]
            let version: Double
        }

        struct Encrypted: Codable {
            let key: String
            let filename: String
            let mimetype: String
        }

        struct Files: Codable {
            let initializationVector: String
            let authenticationTag: String?
            let metadataKey: Int
            let encrypted: String
        }

        let metadata: Metadata
        let files: [String: Files]?
    }

    struct E2eeV12: Codable {

        struct Metadata: Codable {
            let metadataKey: String
            let version: Double
            let checksum: String?
        }

        struct Encrypted: Codable {
            let key: String
            let filename: String
            let mimetype: String
        }

        struct Files: Codable {
            let initializationVector: String
            let authenticationTag: String?
            let encrypted: String
        }

        struct Filedrop: Codable {
            let initializationVector: String
            let authenticationTag: String?
            let encrypted: String
            let encryptedKey: String?
            let encryptedTag: String?
            let encryptedInitializationVector: String?
        }

        let metadata: Metadata
        let files: [String: Files]?
        let filedrop: [String: Filedrop]?
    }

    // --------------------------------------------------------------------------------------------
    // MARK: Ecode JSON Metadata V1.2
    // --------------------------------------------------------------------------------------------

    func encodeMetadataV1(account: String, serverUrl: String, ocIdServerUrl: String) async -> (metadata: String?, signature: String?, counter: Int, error: NKError) {

        let encoder = JSONEncoder()
        var metadataKey: String = ""
        let metadataVersion = 1.2
        var files: [String: E2eeV12.Files] = [:]
        var filesCodable: [String: E2eeV12.Files]?
        var filedrop: [String: E2eeV12.Filedrop] = [:]
        var filedropCodable: [String: E2eeV12.Filedrop]?
        let privateKey = NCPreferences().getEndToEndPrivateKey(account: account)
        var fileNameIdentifiers: [String] = []

        let e2eEncryptions: [tableE2eEncryption]
        do {
            guard try await !database.requiresE2eeV2Async(account: account, serverUrl: serverUrl, ocIdServerUrl: ocIdServerUrl) else {
                throw NCManageDatabase.E2eeStateError.versionDowngrade
            }
            e2eEncryptions = try await database.getUsableE2eEncryptionsAsync(account: account, serverUrl: serverUrl, ocIdServerUrl: ocIdServerUrl)
        } catch {
            return (nil, nil, 0, NKError(errorCode: NCGlobal.shared.errorE2EEVersion, errorDescription: "Invalid or downgraded encrypted metadata."))
        }

        //
        // metadata
        //
        if e2eEncryptions.isEmpty, let key = NCEndToEndEncryption.shared().generateKey() as? NSData {

            if let key = key.base64EncodedString().data(using: .utf8)?.base64EncodedString().data(using: .utf8),
               let metadataKeyEncrypted = NCEndToEndEncryption.shared().encryptAsymmetricData(key, privateKey: privateKey) {
                metadataKey = metadataKeyEncrypted.base64EncodedString()
            }

        } else if let metadatakey = (e2eEncryptions.first!.metadataKey.data(using: .utf8)?.base64EncodedString().data(using: .utf8)),
                  let metadataKeyEncrypted = NCEndToEndEncryption.shared().encryptAsymmetricData(metadatakey, privateKey: privateKey) {

            metadataKey = metadataKeyEncrypted.base64EncodedString()
        }

        for e2eEncryption in e2eEncryptions {

            //
            // files & folders
            //
            if e2eEncryption.blob == "files" || e2eEncryption.blob == "folders" {
                let encrypted = E2eeV12.Encrypted(key: e2eEncryption.key, filename: e2eEncryption.fileName, mimetype: e2eEncryption.mimeType)
                do {
                    // Create "encrypted"
                    var json = try encoder.encode(encrypted)
                    json = json.base64EncodedString().data(using: .utf8)!
                    if let encrypted = NCEndToEndEncryption.shared().encryptPayloadFile(json, key: e2eEncryption.metadataKey) {
                        let record = E2eeV12.Files(initializationVector: e2eEncryption.initializationVector, authenticationTag: e2eEncryption.authenticationTag, encrypted: encrypted)
                        files.updateValue(record, forKey: e2eEncryption.fileNameIdentifier)
                    }
                    fileNameIdentifiers.append(e2eEncryption.fileNameIdentifier)
                } catch let error {
                    return (nil, nil, 0, NKError(errorCode: NCGlobal.shared.errorE2EEJSon, errorDescription: error.localizedDescription))
                }
            }

            //
            // filedrop
            //
            if e2eEncryption.blob == "filedrop" {

                var encryptedKey: String?
                var encryptedInitializationVector: NSString?
                var encryptedTag: NSString?

                if let metadataKeyFiledrop = (e2eEncryption.metadataKey.data(using: .utf8)?.base64EncodedString().data(using: .utf8)),
                   let metadataKeyEncrypted = NCEndToEndEncryption.shared().encryptAsymmetricData(metadataKeyFiledrop, privateKey: privateKey) {
                    encryptedKey = metadataKeyEncrypted.base64EncodedString()
                }
                let encrypted = E2eeV12.Encrypted(key: e2eEncryption.key, filename: e2eEncryption.fileName, mimetype: e2eEncryption.mimeType)
                do {
                    // Create "encrypted"
                    var json = try encoder.encode(encrypted)
                    json = json.base64EncodedString().data(using: .utf8)!
                    if let encrypted = NCEndToEndEncryption.shared().encryptPayloadFile(json, key: e2eEncryption.metadataKey, initializationVector: &encryptedInitializationVector, authenticationTag: &encryptedTag) {
                        let record = E2eeV12.Filedrop(initializationVector: e2eEncryption.initializationVector, authenticationTag: e2eEncryption.authenticationTag, encrypted: encrypted, encryptedKey: encryptedKey, encryptedTag: encryptedTag as? String, encryptedInitializationVector: encryptedInitializationVector as? String)
                        filedrop.updateValue(record, forKey: e2eEncryption.fileNameIdentifier)
                    }
                } catch let error {
                    return (nil, nil, 0, NKError(errorCode: NCGlobal.shared.errorE2EEJSon, errorDescription: error.localizedDescription))
                }
            }
        }

        // Create checksum
        let passphrase = NCPreferences().getEndToEndPassphrase(account: account)?.replacingOccurrences(of: " ", with: "") ?? ""
        let dataChecksum = (passphrase + fileNameIdentifiers.sorted().joined() + metadataKey).data(using: .utf8)
        let checksum = NCEndToEndEncryption.shared().createSHA256(dataChecksum)

        // Create Json
        let metadata = E2eeV12.Metadata(metadataKey: metadataKey, version: metadataVersion, checksum: checksum)
        if !files.isEmpty { filesCodable = files }
        if !filedrop.isEmpty { filedropCodable = filedrop }
        let e2ee = E2eeV12(metadata: metadata, files: filesCodable, filedrop: filedropCodable)
        do {
            let data = try encoder.encode(e2ee)
            let jsonString = String(data: data, encoding: .utf8)
            // Updated metadata to 1.2
            try await self.database.setE2eMetadataAsync(account: account, serverUrl: serverUrl, ocIdServerUrl: ocIdServerUrl, metadataKey: metadataKey, version: metadataVersion)
            return (jsonString, nil, 0, NKError())
        } catch let error {
            return (nil, nil, 0, NKError(errorCode: NCGlobal.shared.errorE2EEJSon, errorDescription: error.localizedDescription))
        }
    }

    /// Both legacy formats are prepared without side effects, then committed with a
    /// sticky-version check under Realm's writer lock to close concurrent downgrades.
    func prepareLegacyMetadata(_ json: String, account: String, serverUrl: String, ocIdServerUrl: String,
                               keySet: NCEndToEndKeySet, requiresV2: Bool) throws -> NCManageDatabase.E2eeLegacySnapshot {
        guard let data = json.data(using: .utf8) else { throw NKError.invalidData }
        let format = try Self.metadataFormat(data, requiresV2: requiresV2)
        guard let crypto = NCEndToEndEncryption.shared() else { throw NKError.invalidData }
        let decoder = JSONDecoder()
        func decryptKey(_ encoded: String) throws -> String {
            guard let ciphertext = Data(base64Encoded: encoded),
                  let decrypted = crypto.decryptAsymmetricData(ciphertext, privateKey: keySet.privateKey),
                  let keyData = Data(base64Encoded: decrypted), let key = String(data: keyData, encoding: .utf8) else {
                throw NKError.invalidData
            }
            return key
        }
        func file(_ identifier: String, payload: Data?, key: String, nonce: String, tag: String?, blob: String = "files", keyIndex: Int = 0) throws -> NCManageDatabase.E2eeFile {
            guard let payload, let data = Data(base64Encoded: payload) else { throw NKError.invalidData }
            let decoded = try decoder.decode(E2eeV1.Encrypted.self, from: data)
            _ = try NCUtilityFileSystem.validatedFileName(identifier)
            _ = try NCUtilityFileSystem.validatedFileName(decoded.filename)
            var file = NCManageDatabase.E2eeFile(identifier: identifier, name: decoded.filename, authenticationTag: tag ?? "",
                key: decoded.key, nonce: nonce, metadataKey: key, mimeType: decoded.mimetype)
            file.blob = blob
            file.metadataKeyIndex = keyIndex
            return file
        }
        var files: [NCManageDatabase.E2eeFile] = []
        let version: Double
        let metadataKey: String
        switch format {
        case .legacyV1:
            let envelope = try decoder.decode(E2eeV1.self, from: data)
            version = envelope.metadata.version
            metadataKey = ""
            var keys: [String: String] = [:]
            for (index, encrypted) in envelope.metadata.metadataKeys { keys[index] = try decryptKey(encrypted) }
            for (identifier, encrypted) in envelope.files ?? [:] {
                guard let key = keys[String(encrypted.metadataKey)] else { throw NKError.invalidData }
                files.append(try file(identifier, payload: crypto.decryptPayloadFile(encrypted.encrypted, key: key), key: key,
                    nonce: encrypted.initializationVector, tag: encrypted.authenticationTag, keyIndex: encrypted.metadataKey))
            }
        case .legacyV12:
            let envelope = try decoder.decode(E2eeV12.self, from: data)
            version = envelope.metadata.version
            metadataKey = try decryptKey(envelope.metadata.metadataKey)
            let passphrase = keySet.passphrase?.replacingOccurrences(of: " ", with: "") ?? ""
            let checksumData = Data((passphrase + (envelope.files ?? [:]).keys.sorted().joined() + envelope.metadata.metadataKey).utf8)
            guard let checksum = crypto.createSHA256(checksumData), envelope.metadata.checksum == checksum else {
                throw NKError(errorCode: NCGlobal.shared.errorE2EEKeyChecksums,
                              errorDescription: NSLocalizedString("_e2ee_no_match_checksum_", comment: ""))
            }
            for (identifier, encrypted) in envelope.files ?? [:] {
                files.append(try file(identifier, payload: crypto.decryptPayloadFile(encrypted.encrypted, key: metadataKey), key: metadataKey,
                    nonce: encrypted.initializationVector, tag: encrypted.authenticationTag))
            }
            for (identifier, encrypted) in envelope.filedrop ?? [:] {
                guard let encodedKey = encrypted.encryptedKey else { throw NKError.invalidData }
                let dropKey = try decryptKey(encodedKey)
                files.append(try file(identifier, payload: crypto.decryptPayloadFile(encrypted.encrypted, key: dropKey,
                    initializationVector: encrypted.encryptedInitializationVector, authenticationTag: encrypted.encryptedTag), key: dropKey,
                    nonce: encrypted.initializationVector, tag: encrypted.authenticationTag, blob: "filedrop"))
            }
        case .v2:
            throw NKError.invalidData
        }
        return .init(account: account, serverUrl: serverUrl, ocIdServerUrl: ocIdServerUrl, version: version, metadataKey: metadataKey, files: files)
    }

    func decodeLegacyMetadata(_ json: String, serverUrl: String, ocIdServerUrl: String,
                              session: NCSession.Session, keySet: NCEndToEndKeySet) async -> NKError {
        do {
            let requiresV2 = try await database.requiresE2eeV2Async(account: session.account, serverUrl: serverUrl, ocIdServerUrl: ocIdServerUrl)
            var snapshot = try prepareLegacyMetadata(json, account: session.account, serverUrl: serverUrl, ocIdServerUrl: ocIdServerUrl,
                                                     keySet: keySet, requiresV2: requiresV2)
            for index in snapshot.files.indices {
                let file = snapshot.files[index]
                let type = await NKTypeIdentifiers.shared.getInternalType(fileName: file.name, mimeType: file.mimeType,
                    directory: file.mimeType == "httpd/unix-directory", account: session.account)
                snapshot.files[index].contentType = type.mimeType
                snapshot.files[index].iconName = type.iconName
                snapshot.files[index].classFile = type.classFile
                snapshot.files[index].typeIdentifier = type.typeIdentifier
            }
            try await database.commitLegacyE2eeSnapshot(snapshot)
            return NKError()
        } catch let error as NKError {
            return error
        } catch {
            return NKError(errorCode: NCGlobal.shared.errorE2EEVersion, errorDescription: "Invalid or downgraded encrypted metadata.")
        }
    }

    func decodeMetadataV12(_ json: String, serverUrl: String, ocIdServerUrl: String,
                           session: NCSession.Session, keySet: NCEndToEndKeySet) async -> NKError {
        await decodeLegacyMetadata(json, serverUrl: serverUrl, ocIdServerUrl: ocIdServerUrl, session: session, keySet: keySet)
    }

    func decodeMetadataV1(_ json: String, serverUrl: String, ocIdServerUrl: String,
                          session: NCSession.Session, keySet: NCEndToEndKeySet) async -> NKError {
        await decodeLegacyMetadata(json, serverUrl: serverUrl, ocIdServerUrl: ocIdServerUrl, session: session, keySet: keySet)
    }
}
