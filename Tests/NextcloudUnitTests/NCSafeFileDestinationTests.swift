// SPDX-FileCopyrightText: Nextcloud GmbH
// SPDX-FileCopyrightText: 2026 Nextcloud contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import Foundation
import Testing
@testable import Nextcloud

@Suite("Document export and share file destinations")
struct NCSafeFileDestinationTests {
    @Test("Untrusted names cannot create paths", arguments: ["", ".", "..", "../outside", "/absolute.pdf", "folder/file.pdf", "folder\\file.pdf", "bad\u{0}name", "line\nfeed"])
    func unsafeNames(name: String) throws {
        let root = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(throws: (any Error).self) { try NCUtilityFileSystem.createDocumentExportURL(fileName: name, in: root) }
        #expect(throws: (any Error).self) { try NCUtilityFileSystem.writeSharedFile(Data("payload".utf8), named: name, in: root) }
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
    }

    @Test("Safe Unicode, spaces and percent characters are literal file names", arguments: ["Résumé 日本語.pdf", "annual report.pdf", "%2e%2e%2fnotes.txt", "100% done.txt"])
    func safeShareNames(name: String) throws {
        let root = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = Data("document".utf8)
        let result = try NCUtilityFileSystem.writeSharedFile(data, named: name, in: root)
        #expect(result == name)
        #expect(try Data(contentsOf: root.appendingPathComponent(result)) == data)
        #expect(!result.contains("/"))
    }

    @Test("Share collisions preserve existing files and return a usable basename")
    func shareCollisions() throws {
        let root = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let original = Data("original".utf8)
        let replacement = Data("new".utf8)
        try original.write(to: root.appendingPathComponent("report.pdf"))
        let result = try NCUtilityFileSystem.writeSharedFile(replacement, named: "report.pdf", in: root)
        #expect(result != "report.pdf")
        #expect((result as NSString).pathExtension == "pdf")
        #expect(!result.contains("/"))
        #expect(try Data(contentsOf: root.appendingPathComponent("report.pdf")) == original)
        #expect(try Data(contentsOf: root.appendingPathComponent(result)) == replacement)
    }

    @Test("Share writes and file copies never follow or replace existing symlinks", arguments: [false, true])
    func shareSymlinks(dangling: Bool) throws {
        let root = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let outside = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: outside) }
        let target = outside.appendingPathComponent("target.txt")
        if !dangling { try Data("original".utf8).write(to: target) }
        let link = root.appendingPathComponent("suggested.txt")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        let written = try NCUtilityFileSystem.writeSharedFile(Data("new".utf8), named: "suggested.txt", in: root)
        let source = outside.appendingPathComponent("source.txt")
        try Data("copy".utf8).write(to: source)
        let copied = try NCUtilityFileSystem.copySharedFile(from: source, named: "suggested.txt", in: root)
        #expect(written != "suggested.txt")
        #expect(copied != "suggested.txt")
        #expect(try link.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink == true)
        #expect(try Data(contentsOf: root.appendingPathComponent(copied)) == Data("copy".utf8))
        if dangling {
            #expect(!FileManager.default.fileExists(atPath: target.path))
        } else {
            #expect(try Data(contentsOf: target) == Data("original".utf8))
        }
    }

    @Test("Failed share writes do not report a filename")
    func failedShareWrite() throws {
        let root = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(throws: (any Error).self) {
            try NCUtilityFileSystem.writeSharedFile(Data("new".utf8), named: "report.txt", in: root.appendingPathComponent("missing"))
        }
        #expect(throws: (any Error).self) {
            try NCUtilityFileSystem.copySharedFile(from: root.appendingPathComponent("missing"), named: "report.txt", in: root)
        }
    }

    @Test("Export downloads are isolated before their initial write and retain names")
    func isolatedExports() throws {
        let root = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let first = try NCUtilityFileSystem.createDocumentExportURL(fileName: "Résumé 日本語.odt", in: root)
        let second = try NCUtilityFileSystem.createDocumentExportURL(fileName: "Résumé 日本語.odt", in: root)
        #expect(first.deletingLastPathComponent() != second.deletingLastPathComponent())
        #expect(first.deletingLastPathComponent().deletingLastPathComponent().path == root.path)
        try Data("export".utf8).write(to: first)
        let result = try NCUtilityFileSystem.finishDocumentExport(at: first, contentDisposition: "attachment; filename=\"Résumé 日本語.pdf\"")
        #expect(result.lastPathComponent == "Résumé 日本語.pdf")
        #expect(result.deletingLastPathComponent() == first.deletingLastPathComponent())
        #expect(try Data(contentsOf: result) == Data("export".utf8))
        try Data("no-header".utf8).write(to: second)
        #expect(try NCUtilityFileSystem.finishDocumentExport(at: second, contentDisposition: nil) == second)
    }

    @Test("Export rename refuses existing files and symlinks", arguments: ["file", "link", "dangling"])
    func exportDestinationCollisions(kind: String) throws {
        let root = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = try NCUtilityFileSystem.createDocumentExportURL(fileName: "document.odt", in: root)
        try Data("export".utf8).write(to: source)
        let outside = root.appendingPathComponent("outside")
        if kind != "dangling" { try Data("original".utf8).write(to: outside) }
        let destination = source.deletingLastPathComponent().appendingPathComponent("result.pdf")
        if kind == "file" {
            try Data("original".utf8).write(to: destination)
        } else {
            try FileManager.default.createSymbolicLink(at: destination, withDestinationURL: outside)
        }
        #expect(throws: (any Error).self) {
            try NCUtilityFileSystem.finishDocumentExport(at: source, contentDisposition: "attachment; filename=result.pdf")
        }
        #expect(try Data(contentsOf: source) == Data("export".utf8))
        if kind != "dangling" { #expect(try Data(contentsOf: outside) == Data("original".utf8)) }
    }

    @Test("A symlink cannot be presented as a completed export")
    func symlinkExportSource() throws {
        let root = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = try NCUtilityFileSystem.createDocumentExportURL(fileName: "document.odt", in: root)
        let outside = root.appendingPathComponent("outside")
        try Data("original".utf8).write(to: outside)
        try FileManager.default.createSymbolicLink(at: source, withDestinationURL: outside)
        #expect(throws: (any Error).self) { try NCUtilityFileSystem.finishDocumentExport(at: source, contentDisposition: nil) }
    }

    @Test("HTTP filename parsing preserves legitimate quoted and extended forms")
    func legitimateContentDisposition() throws {
        #expect(try NCUtilityFileSystem.filenameFromContentDisposition("attachment; filename=\"Quarter 1; résumé.pdf\"; size=10") == "Quarter 1; résumé.pdf")
        #expect(try NCUtilityFileSystem.filenameFromContentDisposition("attachment; FILENAME = \"Résumé 日本語.pdf\"") == "Résumé 日本語.pdf")
        #expect(try NCUtilityFileSystem.filenameFromContentDisposition("attachment; filename=plain.pdf; filename*=UTF-8''R%C3%A9sum%C3%A9%20%E6%97%A5%E6%9C%AC%E8%AA%9E.pdf") == "Résumé 日本語.pdf")
        #expect(try NCUtilityFileSystem.filenameFromContentDisposition("attachment; filename*=UTF-8'en'report%20one.pdf") == "report one.pdf")
        #expect(try NCUtilityFileSystem.filenameFromContentDisposition("attachment; filename=\"quoted\\\" name.pdf\"") == "quoted\" name.pdf")
        #expect(try NCUtilityFileSystem.filenameFromContentDisposition("attachment; filename=%2e%2e%2ffile.pdf") == "%2e%2e%2ffile.pdf")
        #expect(try NCUtilityFileSystem.filenameFromContentDisposition("attachment; filename*=UTF-8''%252e%252e%252ffile.pdf") == "%2e%2e%2ffile.pdf")
        #expect(try NCUtilityFileSystem.filenameFromContentDisposition("attachment") == nil)
    }

    @Test("HTTP path forms are rejected after protocol decoding", arguments: [
        "attachment; filename=../outside", "attachment; filename=/absolute", "attachment; filename=\"folder\\\\file.pdf\"",
        "attachment; filename=.", "attachment; filename=..", "attachment; filename=\"\"",
        "attachment; filename*=UTF-8''%2e%2e%2foutside", "attachment; filename*=UTF-8''%5Coutside",
        "attachment; filename*=UTF-8''%00name", "attachment; filename*=UTF-8''%ZZ",
        "attachment; filename=one; filename=two", "attachment; filename=\"unterminated",
        "attachment; filename=safe; filename*=UTF-8''..%2foutside"
    ])
    func unsafeContentDisposition(header: String) throws {
        let root = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = try NCUtilityFileSystem.createDocumentExportURL(fileName: "document.odt", in: root)
        try Data("export".utf8).write(to: source)
        #expect(throws: (any Error).self) { try NCUtilityFileSystem.finishDocumentExport(at: source, contentDisposition: header) }
        #expect(try Data(contentsOf: source) == Data("export".utf8))
    }

    private func makeDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        return directory
    }
}
