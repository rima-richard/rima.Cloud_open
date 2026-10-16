// SPDX-FileCopyrightText: Nextcloud GmbH
// SPDX-FileCopyrightText: 2026 Nextcloud contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import JavaScriptCore
import Testing
@testable import Nextcloud

@Suite("Rich Documents asset arguments")
@MainActor
struct NCRichDocumentsJavaScriptTests {
    @Test("File names and URLs stay data when the generated script is evaluated", arguments: [
        "Résumé 日本語 and spaces.png", "quote'and\"double.png", "'); injected = true; //",
        "\\'); injected = true; //", "line\nbreak\rwith\ttab", "separator\u{2028}paragraph\u{2029}", "</script><script>injected=true</script>"
    ])
    func assetArguments(value: String) throws {
        let context = try #require(JSContext())
        context.evaluateScript("var injected = false; var received; var OCA = { RichDocuments: { documentsMain: { postAsset: function(name, url) { received = [name, url]; } } } };")
        let url = "https://example.invalid/asset?name=" + value
        let script = try #require(NCViewerDirectEditing.richDocumentsAssetJavaScript(fileName: value, url: url))
        context.evaluateScript(script)
        #expect(context.exception == nil)
        #expect(context.objectForKeyedSubscript("injected")?.toBool() == false)
        let received = try #require(context.objectForKeyedSubscript("received")?.toArray() as? [String])
        #expect(received == [value, url])
    }
}
