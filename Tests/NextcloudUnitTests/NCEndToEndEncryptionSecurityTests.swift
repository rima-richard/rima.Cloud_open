// SPDX-FileCopyrightText: Nextcloud GmbH
// SPDX-FileCopyrightText: 2026 Richard Gittler
// SPDX-License-Identifier: GPL-3.0-or-later

import Foundation
import Testing
@testable import Nextcloud

@Suite("Authenticated E2EE decryption and trusted CMS signers")
struct NCEndToEndEncryptionSecurityTests {
    private let crypto = NCEndToEndEncryption.shared()!

    @Test("New payloads round-trip through both public encryption APIs")
    func payloadRoundTrip() throws {
        let key = NCEndToEndSecurityFixtures.vectors[0].key
        for count in [0, 1, 1024, 4097] {
            let plain = Data(repeating: 42, count: count)
            let legacy = try #require(crypto.encryptPayloadFile(plain, key: key))
            #expect(crypto.decryptPayloadFile(legacy, key: key) == plain)
            var iv: NSString?
            var tag: NSString?
            let payload = try #require(crypto.encryptPayloadFile(plain, key: key, initializationVector: &iv, authenticationTag: &tag))
            let nonce = try #require(iv as String?)
            let authenticationTag = try #require(tag as String?)
            #expect(crypto.decryptPayloadFile(payload, key: key,
                                             initializationVector: nonce,
                                             authenticationTag: authenticationTag) == plain)
        }
    }

    @Test("Both payload formats and legacy 12/16-byte nonces authenticate")
    func validPayloads() throws {
        for vector in NCEndToEndSecurityFixtures.vectors where data(vector.key).count == 16 {
            let expected = data(vector.plain)
            for delimiter in ["|", "fA=="] {
                #expect(crypto.decryptPayloadFile(vector.cipher + delimiter + vector.iv, key: vector.key) == expected)
            }
            for suffix in ["", "|" + vector.iv] {
                #expect(crypto.decryptPayloadFile(vector.cipher + suffix, key: vector.key,
                                                  initializationVector: vector.iv, authenticationTag: vector.tag) == expected)
            }
        }
    }

    @Test("Malformed lengths and repeated nonce suffixes fail without throwing")
    func rejectsMalformedPayloads() throws {
        let vector = NCEndToEndSecurityFixtures.vectors[0]
        for payload in ["", "!", "AA==", Data(repeating: 0, count: 15).base64EncodedString()] {
            #expect(crypto.decryptPayloadFile(payload + "|" + vector.iv, key: vector.key) == nil)
            #expect(crypto.decryptPayloadFile(payload, key: vector.key, initializationVector: vector.iv, authenticationTag: vector.tag) == nil)
        }
        for count in [0, 1, 15, 17, 31, 32, 4096] {
            let key = Data(repeating: 0, count: count).base64EncodedString()
            #expect(crypto.decryptPayloadFile(vector.cipher, key: key, initializationVector: vector.iv, authenticationTag: vector.tag) == nil)
            #expect(crypto.encryptPayloadFile(Data("control".utf8), key: key) == nil)
        }
        for count in [0, 1, 11, 13, 15, 17, 1_048_576] {
            let iv = Data(repeating: 0, count: count).base64EncodedString()
            #expect(crypto.decryptPayloadFile(vector.cipher, key: vector.key, initializationVector: iv, authenticationTag: vector.tag) == nil)
        }
        for count in [0, 1, 15, 17, 1_048_576] {
            let tag = Data(repeating: 0, count: count).base64EncodedString()
            #expect(crypto.decryptPayloadFile(vector.cipher, key: vector.key, initializationVector: vector.iv, authenticationTag: tag) == nil)
        }
        #expect(crypto.decryptPayloadFile(vector.cipher + "|" + vector.iv + "|" + vector.iv,
                                         key: vector.key, initializationVector: vector.iv, authenticationTag: vector.tag) == nil)
    }

    @Test("Tampered ciphertext and tags never return plaintext")
    func rejectsTamperedPayloads() throws {
        let vector = NCEndToEndSecurityFixtures.vectors[0]
        var ciphertext = data(vector.cipher)
        ciphertext[0] ^= 1
        #expect(crypto.decryptPayloadFile(ciphertext.base64EncodedString() + "|" + vector.iv, key: vector.key) == nil)
        #expect(crypto.decryptPayloadFile(ciphertext.base64EncodedString(), key: vector.key,
                                         initializationVector: vector.iv, authenticationTag: vector.tag) == nil)
        ciphertext = data(vector.cipher)
        ciphertext[ciphertext.count - 1] ^= 1
        let tamperedTag = ciphertext.suffix(16).base64EncodedString()
        #expect(crypto.decryptPayloadFile(ciphertext.base64EncodedString() + "|" + vector.iv, key: vector.key) == nil)
        #expect(crypto.decryptPayloadFile(ciphertext.base64EncodedString(), key: vector.key,
                                         initializationVector: vector.iv, authenticationTag: tamperedTag) == nil)
    }

    @Test("Private-key AES-256 and both PBKDF2 formats remain compatible")
    func privateKeyCompatibility() {
        for payload in NCEndToEndSecurityFixtures.privateKeyPayloads {
            #expect(crypto.decryptPrivateKey(payload, passphrase: "test-passphrase") == Data("private-key-control".utf8))
            #expect(crypto.decryptPrivateKey(payload, passphrase: "incorrect") == nil)
        }
        for payload in ["", "!|!|!", "AA==|AA==|AA=="] {
            #expect(crypto.decryptPrivateKey(payload, passphrase: "test-passphrase") == nil)
        }
    }

    @Test("Files publish only authenticated plaintext, including empty and legacy files")
    func filePublication() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let input = directory.appendingPathComponent("cipher")
        let output = directory.appendingPathComponent("plain")
        for vector in NCEndToEndSecurityFixtures.vectors {
            for appendTag in [true, false] {
                let ciphertext = data(vector.cipher)
                try (appendTag ? ciphertext : Data(ciphertext.dropLast(16))).write(to: input)
                #expect(decrypt(input: input, output: output, vector: vector))
                #expect(try Data(contentsOf: output) == data(vector.plain))
                #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted() == ["cipher", "plain"])
                try FileManager.default.removeItem(at: output)
            }
        }
    }

    @Test("Authentication and I/O failure preserve an existing output and remove staging files")
    func failedFilesAreNotPublished() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let input = directory.appendingPathComponent("cipher")
        let output = directory.appendingPathComponent("plain")
        let vector = NCEndToEndSecurityFixtures.vectors[0]
        let previous = Data("previous authenticated content".utf8)
        for tamperTag in [true, false] {
            var corrupted = data(vector.cipher)
            corrupted[tamperTag ? corrupted.count - 1 : 0] ^= 1
            try corrupted.write(to: input)
            #expect(!decrypt(input: input, output: output, vector: vector))
            #expect(!FileManager.default.fileExists(atPath: output.path))
            try previous.write(to: output)
            #expect(!decrypt(input: input, output: output, vector: vector))
            #expect(try Data(contentsOf: output) == previous)
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted() == ["cipher", "plain"])
            try FileManager.default.removeItem(at: output)
        }
        try data(vector.cipher).write(to: input)
        let missingParent = directory.appendingPathComponent("missing/plain")
        #expect(!decrypt(input: input, output: missingParent, vector: vector))
        // Publication fails when the destination is a directory; the staging file is still removed.
        #expect(!decrypt(input: input, output: directory, vector: vector))
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["cipher"])
        for count in [0, 1, 15, 17] {
            #expect(!crypto.decryptFile(input.path, fileNamePlain: output.path,
                                        key: Data(repeating: 0, count: count), keyLen: 16,
                                        initializationVector: data(vector.iv), authenticationTag: data(vector.tag)))
        }
        #expect(!FileManager.default.fileExists(atPath: output.path))
    }

    @Test("Downloads reject historical unverified keys even when ciphertext authenticates")
    func downloadKeyProvenance() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let input = directory.appendingPathComponent("cipher")
        let output = directory.appendingPathComponent("plain")
        let vector = NCEndToEndSecurityFixtures.vectors[0]
        try data(vector.cipher).write(to: input)
        let encryption = tableE2eEncryption(account: "provenance-test", ocIdServerUrl: "root", fileNameIdentifier: "cipher")
        encryption.key = vector.key
        encryption.initializationVector = vector.iv
        encryption.authenticationTag = vector.tag

        for version in ["", "2", "2.0", "1.invalid"] {
            encryption.version = version
            #expect(!NCNetworking.authenticateDownloadedFile(at: input.path, fileNameView: output.lastPathComponent, encryption: encryption, requiresV2: false))
            #expect(!FileManager.default.fileExists(atPath: output.path))
        }

        // Genuine legacy records remain usable only outside a previously observed V2 root.
        encryption.version = "1.2"
        #expect(NCNetworking.authenticateDownloadedFile(at: input.path, fileNameView: output.lastPathComponent, encryption: encryption, requiresV2: false))
        #expect(try Data(contentsOf: output) == data(vector.plain))
        try FileManager.default.removeItem(at: output)
        #expect(!NCNetworking.authenticateDownloadedFile(at: input.path, fileNameView: output.lastPathComponent, encryption: encryption, requiresV2: true))
        #expect(!FileManager.default.fileExists(atPath: output.path))

        // Both verified snapshots and newly generated local uploads carry explicit provenance.
        encryption.version = "2"
        for local in [false, true] {
            encryption.authenticated = !local
            encryption.locallyGenerated = local
            #expect(NCNetworking.authenticateDownloadedFile(at: input.path, fileNameView: output.lastPathComponent, encryption: encryption, requiresV2: true))
            #expect(try Data(contentsOf: output) == data(vector.plain))
            try FileManager.default.removeItem(at: output)
        }

        // A purged or missing row cannot turn a sticky V2 download into a plain-file success.
        #expect(!NCNetworking.authenticateDownloadedFile(at: input.path, fileNameView: "plain", encryption: nil, requiresV2: true, encrypted: false))
        #expect(!NCNetworking.authenticateDownloadedFile(at: input.path, fileNameView: "plain", encryption: nil, requiresV2: false, encrypted: true))
        #expect(NCNetworking.authenticateDownloadedFile(at: input.path, fileNameView: "plain", encryption: nil, requiresV2: false, encrypted: false))
        #expect(!FileManager.default.fileExists(atPath: output.path))

        encryption.authenticated = true
        for name in ["../outside", "/outside", "nested/plain", "nested\\plain", ".", "..", ""] {
            #expect(!NCNetworking.authenticateDownloadedFile(at: input.path, fileNameView: name, encryption: encryption, requiresV2: true))
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["cipher"])

        let previous = Data("previous authenticated content".utf8)
        try previous.write(to: output)
        encryption.authenticated = false
        encryption.locallyGenerated = false
        #expect(!NCNetworking.authenticateDownloadedFile(at: input.path, fileNameView: output.lastPathComponent, encryption: encryption, requiresV2: true))
        #expect(try Data(contentsOf: output) == previous)
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted() == ["cipher", "plain"])
    }

    @Test("CMS verifies the expected public key, including certificate renewal")
    func expectedSigner() {
        let signature = data(NCEndToEndSecurityFixtures.signature)
        let payload = Data("authenticated-metadata".utf8)
        for expected in [NCEndToEndSecurityFixtures.certificate, NCEndToEndSecurityFixtures.publicKey, NCEndToEndSecurityFixtures.renewedCertificate] {
            #expect(crypto.verifySignatureCMS(signature, data: payload, certificates: [expected]))
        }
        #expect(crypto.verifySignatureCMS(signature, data: payload, certificates: [NCEndToEndSecurityFixtures.otherCertificate, NCEndToEndSecurityFixtures.certificate]))
        #expect(!crypto.verifySignatureCMS(signature, data: Data("tampered-metadata".utf8), certificates: [NCEndToEndSecurityFixtures.certificate]))
    }

    @Test("A different key with the same subject, issuer and serial is not trusted")
    func unexpectedSigner() {
        let signature = data(NCEndToEndSecurityFixtures.signature)
        let payload = Data("authenticated-metadata".utf8)
        for certificates in [[], ["malformed"], [NCEndToEndSecurityFixtures.otherCertificate], [NCEndToEndSecurityFixtures.otherPublicKey]] {
            #expect(!crypto.verifySignatureCMS(signature, data: payload, certificates: certificates))
        }
        for malformed in [Data(), Data([0]), Data("garbage".utf8), Data(signature.dropLast())] {
            #expect(!crypto.verifySignatureCMS(malformed, data: payload, certificates: [NCEndToEndSecurityFixtures.certificate]))
        }
    }

    @Test("Certificate extraction returns stable SPKI and rejects malformed input")
    func certificatePublicKey() {
        #expect(crypto.extractPublicKey(fromCertificate: NCEndToEndSecurityFixtures.certificate) == NCEndToEndSecurityFixtures.publicKey + "\n")
        #expect(crypto.extractPublicKey(fromCertificate: NCEndToEndSecurityFixtures.renewedCertificate) == NCEndToEndSecurityFixtures.publicKey + "\n")
        for malformed in ["", "garbage", "-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----"] {
            #expect(crypto.extractPublicKey(fromCertificate: malformed) == nil)
        }
    }

    private func data(_ base64: String) -> Data { Data(base64Encoded: base64)! }

    private func decrypt(input: URL, output: URL, vector: (key: String, iv: String, cipher: String, tag: String, plain: String)) -> Bool {
        let key = data(vector.key)
        return crypto.decryptFile(input.path, fileNamePlain: output.path, key: key, keyLen: Int32(key.count),
                                  initializationVector: data(vector.iv), authenticationTag: data(vector.tag))
    }

}
