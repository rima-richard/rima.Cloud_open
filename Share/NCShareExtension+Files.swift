// SPDX-FileCopyrightText: Nextcloud GmbH
// SPDX-FileCopyrightText: 2021 Marino Faggiana
// SPDX-FileCopyrightText: 2021 Henrik Storch
// SPDX-License-Identifier: GPL-3.0-or-later

import Foundation
import UIKit
import UniformTypeIdentifiers
import NextcloudKit

extension NCShareExtension {
    func reloadData() async {
        let session = NCShareExtensionData.shared.getSession()
        let layoutForView = NCManageDatabase.shared.getLayoutForView(account: session.account, key: keyLayout, serverUrl: serverUrl)
        let showHiddenFiles = NCPreferences().getShowHiddenFiles(account: session.account)
        let predicate = showHiddenFiles
            ? NSPredicate(
                format: "account == %@ AND serverUrl == %@ AND fileName != %@ AND directory == true",
                session.account,
                serverUrl,
                NextcloudKit.shared.nkCommonInstance.rootFileName
            )
            : NSPredicate(
                format: "account == %@ AND serverUrl == %@ AND fileName != %@ AND directory == true AND NOT fileName BEGINSWITH[c] %@",
                session.account,
                serverUrl,
                NextcloudKit.shared.nkCommonInstance.rootFileName,
                "."
            )

        let metadatas = await NCManageDatabase.shared.getMetadatasAsync(predicate: predicate,
                                                                        withLayout: layoutForView,
                                                                        withAccount: session.account)
        self.dataSource = NCCollectionViewDataSource(metadatas: metadatas,
                                                     layoutForView: layoutForView,
                                                     account: session.account)
        self.collectionView.reloadData()
    }

    @objc func didCreateFolder(_ notification: NSNotification) {
        Task {
            guard let userInfo = notification.userInfo as NSDictionary?,
                  let ocId = userInfo["ocId"] as? String,
                  let metadata = await NCManageDatabase.shared.getMetadataFromOcIdAsync(ocId)
            else { return }

            self.serverUrl += "/" + metadata.fileName
            await self.loadFolder()
            self.setNavigationBar(navigationTitle: metadata.fileNameView)
        }
    }

    func loadFolder() async {
        let session = NCShareExtensionData.shared.getSession()
        let resultsReadFolder = await NCNetworking.shared.readFolderAsync(serverUrl: serverUrl, account: session.account) { task in
            self.dataSourceTask = task
            self.collectionView.reloadData()
        }

        if resultsReadFolder.error == .success {
            self.metadataFolder = resultsReadFolder.metadataFolder
            await self.reloadData()
        } else {
            self.showAlert(description: resultsReadFolder.error.errorDescription)
        }
    }
}

class NCFilesExtensionHandler {
    var itemsProvider: [NSItemProvider] = []
    lazy var fileNames: [String] = []
    let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH-mm-ss-"
        return formatter
    }()

    @discardableResult
    init(items: [NSExtensionItem], completion: @escaping ([String]) -> Void) {
        NCUtilityFileSystem().emptyTemporaryDirectory()
        var counter = 0

        self.itemsProvider = items.compactMap({ $0.attachments }).flatMap { $0.filter({
            $0.hasItemConformingToTypeIdentifier(UTType.item.identifier as String) || $0.hasItemConformingToTypeIdentifier("public.url")
        }) }

        for (ix, provider) in itemsProvider.enumerated() {
            provider.loadItem(forTypeIdentifier: provider.typeIdentifier) { [self] item, error in
                defer {
                    counter += 1
                    if counter == itemsProvider.count { completion(self.fileNames) }
                }
                guard error == nil else { return }
                var originalName = (dateFormatter.string(from: Date())) + String(ix)

                if let url = item as? URL, url.isFileURL, !url.lastPathComponent.isEmpty {
                    originalName = url.lastPathComponent

                    if fileNames.contains(originalName) {
                        let incrementalNumber = NCPreferences().incrementalNumber
                        originalName = "\(url.deletingPathExtension().lastPathComponent) \(incrementalNumber).\(url.pathExtension)"
                    }
                }

                var fileName: String?
                switch item {
                case let image as UIImage:
                    fileName = getItem(image: image, fileName: originalName)
                case let url as URL:
                    fileName = getItem(url: url, fileName: originalName)
                case let data as Data:
                    fileName = getItem(data: data, fileName: originalName, provider: provider)
                case let text as String:
                    fileName = getItem(string: text, fileName: originalName)
                default: return
                }

                if let fileName, !fileNames.contains(fileName) {
                    fileNames.append(fileName)
                }
            }
        }
    }

    // Image
    func getItem(image: UIImage, fileName: String) -> String? {
        guard (try? NCUtilityFileSystem.validatedFileName(fileName)) != nil,
              let pngImageData = image.pngData() else { return nil }
        let name = (fileName as NSString).pathExtension.isEmpty ? fileName + ".png" : fileName
        return try? NCUtilityFileSystem.writeSharedFile(pngImageData, named: name)
    }

    // URL
    // Does not work for directories
    func getItem(url: URL, fileName: String) -> String? {
        var fileName = fileName
        guard url.isFileURL else {
            guard !fileNames.contains(url.lastPathComponent) else { return nil }
            if !url.deletingPathExtension().lastPathComponent.isEmpty { fileName = url.deletingPathExtension().lastPathComponent }
            fileName += "." + (url.pathExtension.isEmpty ? "html" : url.pathExtension)
            do {
                let downloadedContent = try Data(contentsOf: url)
                return try NCUtilityFileSystem.writeSharedFile(downloadedContent, named: fileName)
            } catch { print(error); return nil }
        }
        return try? NCUtilityFileSystem.copySharedFile(from: url, named: fileName)
    }

    // Data
    func getItem(data: Data, fileName: String, provider: NSItemProvider) -> String? {
        guard !data.isEmpty else { return nil }
        var fileName = fileName

        guard (try? NCUtilityFileSystem.validatedFileName(fileName)) != nil else { return nil }
        if (fileName as NSString).pathExtension.isEmpty {
            if let name = provider.suggestedName {
                fileName = name
            } else if let ext = provider.registeredTypeIdentifiers.last?.split(separator: ".").last {
                fileName += "." + ext
            } // else: no file information, use default name without ext
        }
        guard (try? NCUtilityFileSystem.validatedFileName(fileName)) != nil else { return nil }

        // when sharing images in safari only data is retuned.
        // also, when sharing option "Automatic" is slected extension will return both raw data and a url, which will be downloaded, causing the image to appear twice with different names
        if let image = UIImage(data: data) {
            return getItem(image: image, fileName: fileName)
        }

        return try? NCUtilityFileSystem.writeSharedFile(data, named: fileName)
    }

    // String
    func getItem(string: String, fileName: String) -> String? {
        guard !string.isEmpty,
              (try? NCUtilityFileSystem.validatedFileName(fileName)) != nil else { return nil }
        return try? NCUtilityFileSystem.writeSharedFile(Data(string.utf8), named: fileName + ".txt")
    }
}

extension NSItemProvider {
    var typeIdentifier: String {
        if hasItemConformingToTypeIdentifier("public.url") { return "public.url" } else
        if hasItemConformingToTypeIdentifier(UTType.item.identifier as String) { return UTType.item.identifier as String } else { return "" }
    }
}
