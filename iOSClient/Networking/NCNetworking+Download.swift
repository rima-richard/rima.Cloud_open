// SPDX-FileCopyrightText: Nextcloud GmbH
// SPDX-FileCopyrightText: 2024 Marino Faggiana
// SPDX-License-Identifier: GPL-3.0-or-later

import UIKit
import NextcloudKit
import Alamofire
import RealmSwift

extension NCNetworking {

    // MARK: - Download file in foreground

    @discardableResult
    func downloadFile(metadata: tableMetadata,
                      requestHandler: @escaping (_ request: DownloadRequest) -> Void = { _ in },
                      taskHandler: @escaping (_ task: URLSessionTask) -> Void = { _ in },
                      progressHandler: @escaping (_ progress: Progress) -> Void = { _ in })
    async -> (account: String,
              etag: String?,
              date: Date?,
              length: Int64,
              nkError: NKError ) {
        let options = NKRequestOptions(queue: nkComm.backgroundQueue)
        let fileNameLocalPath = utilityFileSystem.getDirectoryProviderStorageOcId(metadata.ocId, fileName: metadata.fileName, userId: metadata.userId, urlBase: metadata.urlBase)

        if metadata.status == global.metadataStatusDownloading || metadata.status == global.metadataStatusUploading {
            return(metadata.account, metadata.etag, metadata.date as Date, metadata.size, .success)
        }

        await updateMetadataPlaceholder(metadata)

        let results = await NextcloudKit.shared.downloadAsync(serverUrlFileName: metadata.serverUrlFileName,
                                                              fileNameLocalPath: fileNameLocalPath,
                                                              account: metadata.account,
                                                              options: options) { request in
            requestHandler(request)
        } taskHandler: { task in
            Task {
                await NCManageDatabase.shared.setMetadataSessionAsync(
                    ocId: metadata.ocId,
                    session: self.sessionDownload,
                    sessionTaskIdentifier: task.taskIdentifier,
                    status: self.global.metadataStatusDownloading)

                await self.transferDispatcher.notifyAllDelegates { delegate in
                    delegate.transferChange(networkingStatus: self.global.networkingStatusDownloading,
                                            account: metadata.account,
                                            fileName: metadata.fileName,
                                            serverUrl: metadata.serverUrl,
                                            selector: metadata.sessionSelector,
                                            ocId: metadata.ocId,
                                            destination: nil,
                                            error: .success)
                }
            }
            taskHandler(task)
        } progressHandler: { progress in
            Task {
                guard await self.progressQuantizer.shouldEmit(serverUrlFileName: metadata.serverUrlFileName, fraction: progress.fractionCompleted) else {
                    return
                }
                await self.transferDispatcher.notifyAllDelegates { delegate in
                    delegate.transferProgressDidUpdate(progress: Float(progress.fractionCompleted),
                                                       totalBytes: progress.totalUnitCount,
                                                       totalBytesExpected: progress.completedUnitCount,
                                                       fileName: metadata.fileName,
                                                       serverUrl: metadata.serverUrl)
                }
            }
            progressHandler(progress)
        }

        await progressQuantizer.clear(serverUrlFileName: metadata.serverUrlFileName)
        let allHeaderFields = results.response?.response?.allHeaderFields
        let etag = nkComm.normalizedETag(nkComm.findHeader("oc-etag", allHeaderFields: allHeaderFields))

        let completionError: NKError
        if results.nkError == .success {
            completionError = await downloadSuccess(withMetadata: metadata, etag: etag)
        } else {
            completionError = results.nkError
            await downloadError(withMetadata: metadata, error: completionError)
        }

        return(metadata.account, etag, metadata.date as Date, metadata.size, completionError)
    }

    // MARK: - Download file in background

    @discardableResult
    func downloadFileInBackground(metadata: tableMetadata,
                                  taskHandler: @escaping (_ task: URLSessionDownloadTask?) -> Void = { _ in },
                                  start: @escaping () -> Void = { }) async -> NKError {
        let fileNameLocalPath = utilityFileSystem.getDirectoryProviderStorageOcId(metadata.ocId, fileName: metadata.fileName, userId: metadata.userId, urlBase: metadata.urlBase)

        start()

        let (task, error) = await backgroundSession.downloadAsync(serverUrlFileName: metadata.serverUrlFileName,
                                                                  fileNameLocalPath: fileNameLocalPath,
                                                                  account: metadata.account,
                                                                  sessionIdentifier: sessionDownloadBackground)

        taskHandler(task)

        if let task, error == .success {
            nkLog(debug: " Downloading file \(metadata.fileNameView) with task with taskIdentifier \(task.taskIdentifier)")

            await NCManageDatabase.shared.setMetadataSessionAsync(ocId: metadata.ocId,
                                                                  session: self.sessionDownloadBackground,
                                                                  sessionTaskIdentifier: task.taskIdentifier,
                                                                  status: self.global.metadataStatusDownloading)

            await self.transferDispatcher.notifyAllDelegates { delegate in
                delegate.transferChange(networkingStatus: self.global.networkingStatusDownloading,
                                        account: metadata.account,
                                        fileName: metadata.fileName,
                                        serverUrl: metadata.serverUrl,
                                        selector: metadata.sessionSelector,
                                        ocId: metadata.ocId,
                                        destination: nil,
                                        error: .success)
            }
        } else {
            _ = await NCManageDatabase.shared.setMetadataSessionAsync(ocId: metadata.ocId,
                                                                      session: "",
                                                                      sessionTaskIdentifier: 0,
                                                                      sessionError: "",
                                                                      selector: "",
                                                                      status: self.global.metadataStatusNormal)
        }

        return(error)
    }

    // MARK: - DOWNLOAD SUCCESS

    // Shared by immediate completion and the foreground batch queue.
    func authenticateDownloadedFile(withMetadata metadata: tableMetadata) async -> NKError {
#if !EXTENSION
        let failure = NKError(errorCode: global.errorE2EEKeyCiphertext,
                              errorDescription: NSLocalizedString("_e2ee_key_ciphertext_", comment: ""))
        let encryption = await NCManageDatabase.shared.getE2eEncryptionAsync(
            predicate: NSPredicate(format: "account == %@ AND fileNameIdentifier == %@ AND serverUrl == %@",
                                   metadata.account, metadata.fileName, metadata.serverUrl))
        let requiresV2: Bool
        do {
            // Query the persisted folder/ancestor state even when a snapshot removed the file key.
            requiresV2 = try await NCManageDatabase.shared.requiresE2eeV2Async(
                account: metadata.account, serverUrl: metadata.serverUrl, ocIdServerUrl: encryption?.ocIdServerUrl ?? "")
        } catch {
            await NCManageDatabase.shared.deleteLocalFileAsync(id: metadata.ocId)
            return failure
        }
        let source = utilityFileSystem.getDirectoryProviderStorageOcId(metadata.ocId, fileName: metadata.fileName,
                                                                      userId: metadata.userId, urlBase: metadata.urlBase)
        guard Self.authenticateDownloadedFile(at: source, fileNameView: metadata.fileNameView, encryption: encryption,
                                            requiresV2: requiresV2, encrypted: metadata.e2eEncrypted) else {
            await NCManageDatabase.shared.deleteLocalFileAsync(id: metadata.ocId)
            return failure
        }
#endif
        return .success
    }

#if !EXTENSION
    // Historical V2 rows may contain attacker-selected keys written before signature verification.
    // Authenticate their provenance before allowing even mathematically valid ciphertext to publish.
    static func authenticateDownloadedFile(at source: String, fileNameView: String,
                                           encryption: tableE2eEncryption?, requiresV2: Bool, encrypted: Bool = false) -> Bool {
        guard (try? NCUtilityFileSystem.validatedFileName(fileNameView)) != nil else { return false }
        guard let encryption else { return !encrypted && !requiresV2 }
        let directory = URL(fileURLWithPath: source).deletingLastPathComponent()
        guard let destination = try? NCUtilityFileSystem.containedFileURL(named: fileNameView, in: directory) else { return false }
        let version = Double(encryption.version)
        let isLegacy = version.map { $0 >= 1 && $0 < 2 } ?? false
        guard encryption.isUsableForE2eeV2 || (!requiresV2 && isLegacy),
              let key = Data(base64Encoded: encryption.key),
              let iv = Data(base64Encoded: encryption.initializationVector),
              let tag = Data(base64Encoded: encryption.authenticationTag) else {
            return false
        }
        return NCEndToEndEncryption.shared().decryptFile(source, fileNamePlain: destination.path,
                                                        key: key, keyLen: 16, initializationVector: iv,
                                                        authenticationTag: tag)
    }
#endif

    @discardableResult
    func downloadSuccess(withMetadata metadata: tableMetadata, etag: String?) async -> NKError {
        let error = await authenticateDownloadedFile(withMetadata: metadata)
        guard error == .success else {
            await downloadError(withMetadata: metadata, error: error)
            return error
        }
        nkLog(success: "Downloaded file: " + metadata.serverUrlFileName)

        await NCManageDatabase.shared.addLocalFilesAsync(metadatas: [metadata])

        await NCManageDatabase.shared.setMetadataSessionAsync(ocId: metadata.ocId,
                                                              session: "",
                                                              sessionTaskIdentifier: 0,
                                                              sessionError: "",
                                                              status: self.global.metadataStatusNormal,
                                                              etag: etag)

        await self.transferDispatcher.notifyAllDelegates { delegate in
            delegate.transferChange(networkingStatus: self.global.networkingStatusDownloaded,
                                    account: metadata.account,
                                    fileName: metadata.fileName,
                                    serverUrl: metadata.serverUrl,
                                    selector: metadata.sessionSelector,
                                    ocId: metadata.ocId,
                                    destination: nil,
                                    error: .success)
        }
        return .success
    }

    // MARK: - DOWNLOAD ERROR

    func downloadError(withMetadata metadata: tableMetadata, error: NKError) async {
        await nkComm.appendServerErrorAccount(metadata.account, errorCode: error.errorCode)

        nkLog(error: "Downloaded file: " + metadata.serverUrlFileName + ", result: error \(error.errorCode)")

        if error.errorCode == NCGlobal.shared.errorResourceNotFound {
            self.utilityFileSystem.removeFile(atPath: self.utilityFileSystem.getDirectoryProviderStorageOcId(metadata.ocId, userId: metadata.userId, urlBase: metadata.urlBase))

            await NCManageDatabase.shared.deleteLocalFileAsync(id: metadata.ocId)
            await NCManageDatabase.shared.deleteMetadataAsync(id: metadata.ocId)
        } else if error.errorCode == NSURLErrorCancelled {
            await NCManageDatabase.shared.setMetadataSessionAsync(ocId: metadata.ocId,
                                                                  session: "",
                                                                  sessionTaskIdentifier: 0,
                                                                  sessionError: "",
                                                                  selector: "",
                                                                  status: self.global.metadataStatusNormal)

            await self.transferDispatcher.notifyAllDelegates { delegate in
                    delegate.transferChange(networkingStatus: self.global.networkingStatusDownloadCancel,
                                            account: metadata.account,
                                            fileName: metadata.fileName,
                                            serverUrl: metadata.serverUrl,
                                            selector: metadata.sessionSelector,
                                            ocId: metadata.ocId,
                                            destination: nil,
                                            error: .success)
                }
        } else {
           await NCManageDatabase.shared.setMetadataSessionAsync(ocId: metadata.ocId,
                                                                 session: "",
                                                                 sessionTaskIdentifier: 0,
                                                                 sessionError: "",
                                                                 selector: "",
                                                                 status: self.global.metadataStatusNormal)

            await self.transferDispatcher.notifyAllDelegates { delegate in
                delegate.transferChange(networkingStatus: NCGlobal.shared.networkingStatusDownloaded,
                                        account: metadata.account,
                                        fileName: metadata.fileName,
                                        serverUrl: metadata.serverUrl,
                                        selector: metadata.sessionSelector,
                                        ocId: metadata.ocId,
                                        destination: nil,
                                        error: error)
            }
        }
    }

    // MARK: - Synchronization Download

    internal func synchronizationDownload(account: String,
                                          serverUrl: String,
                                          userId: String,
                                          urlBase: String,
                                          metadatasInDownload: [tableMetadata]?) async {
        let results = await NextcloudKit.shared.readFileOrFolderAsync(
            serverUrlFileName: serverUrl,
            depth: "infinity",
            showHiddenFiles: NCPreferences().getShowHiddenFiles(account: account),
            account: account
        )

        guard results.error == .success, let files = results.files else {
            nkLog(tag: self.global.logTagSync,
                  emoji: .error,
                  message: "Read infinite folder: \(serverUrl), error: \(results.error.errorCode)")
            return
        }

        nkLog(tag: self.global.logTagSync,
              emoji: .success,
              message: "Read infinite folder: \(serverUrl)")

        let ocIdsInDownload = Set(metadatasInDownload?.map(\.ocId) ?? [])
        var directoriesToCreate: [tableMetadata] = []
        var metadatasToDownload: [tableMetadata] = []

        for file in files {
            let metadata = await NCManageDatabaseCreateMetadata().convertFileToMetadataAsync(file)

            if file.directory {
                directoriesToCreate.append(metadata)
                continue
            }

            guard await isFileDifferent(ocId: file.ocId,
                                        fileName: file.fileName,
                                        etag: file.etag,
                                        ocIdsInDownload: ocIdsInDownload,
                                        userId: userId,
                                        urlBase: urlBase) else {
                continue
            }

            metadata.session = self.sessionDownloadBackground
            metadata.sessionSelector = NCGlobal.shared.selectorSynchronizationOffline
            metadata.sessionTaskIdentifier = 0
            metadata.sessionError = ""
            metadata.status = NCGlobal.shared.metadataStatusWaitDownload
            metadata.sessionDate = Date()

            metadatasToDownload.append(metadata)
        }

        await NCManageDatabase.shared.createDirectoriesAsync(metadatas: directoriesToCreate)
        await NCManageDatabase.shared.addMetadatasAsync(metadatasToDownload)

        nkLog(tag: self.global.logTagSync,
              emoji: .start,
              message: "Queued \(metadatasToDownload.count) files for offline synchronization: \(serverUrl)")

    }

    internal func isFileDifferent(ocId: String,
                                  fileName: String,
                                  etag: String,
                                  ocIdsInDownload: Set<String>,
                                  userId: String,
                                  urlBase: String) async -> Bool {
        if ocIdsInDownload.contains(ocId) {
            return false
        }

        guard let localFile = await NCManageDatabase.shared.getTableLocalFileAsync(predicate: NSPredicate(format: "ocId == %@", ocId)) else {
            return true
        }

        let fileNamePath = self.utilityFileSystem.getDirectoryProviderStorageOcId(ocId,
                                                                                  fileName: fileName,
                                                                                  userId: userId,
                                                                                  urlBase: urlBase)
        let size = await utilityFileSystem.fileSizeAsync(atPath: fileNamePath)

        return localFile.etag != etag || size == 0
    }

    // MARK: - Download for Offline

    func setMetadataAvalableOffline(_ metadata: tableMetadata, isOffline: Bool) async {
        if isOffline {
            if metadata.directory {
                await NCManageDatabase.shared.setDirectoryAsync(serverUrl: metadata.serverUrlFileName, offline: false, metadata: metadata)
                let predicate = NSPredicate(format: "account == %@ AND serverUrl BEGINSWITH %@ AND sessionSelector == %@ AND status == %d", metadata.account, metadata.serverUrlFileName, NCGlobal.shared.selectorSynchronizationOffline, NCGlobal.shared.metadataStatusWaitDownload)
                if let metadatas = await NCManageDatabase.shared.getMetadatasAsync(predicate: predicate) {
                    await NCManageDatabase.shared.clearMetadatasSessionAsync(metadatas: metadatas)
                }
            } else {
                await NCManageDatabase.shared.setOffLocalFileAsync(ocId: metadata.ocId)
            }
        } else if metadata.directory {
            await NCManageDatabase.shared.cleanTablesOcIds(account: metadata.account, userId: metadata.userId, urlBase: metadata.urlBase)
            await NCManageDatabase.shared.setDirectoryAsync(serverUrl: metadata.serverUrlFileName, offline: true, metadata: metadata)
            await NCNetworking.shared.synchronizationDownload(account: metadata.account, serverUrl: metadata.serverUrlFileName, userId: metadata.userId, urlBase: metadata.urlBase, metadatasInDownload: nil)
        } else {
            var metadatasSynchronizationOffline: [tableMetadata] = []
            metadatasSynchronizationOffline.append(metadata)
            if let metadata = await NCManageDatabase.shared.getMetadataLivePhotoAsync(metadata: metadata) {
                metadatasSynchronizationOffline.append(metadata)
            }
            await NCManageDatabase.shared.addLocalFilesAsync(metadatas: [metadata], offline: true)
            for metadata in metadatasSynchronizationOffline {
                await NCManageDatabase.shared.setMetadataSessionInWaitDownloadAsync(ocId: metadata.ocId,
                                                                                    session: NCNetworking.shared.sessionDownloadBackground,
                                                                                    selector: NCGlobal.shared.selectorSynchronizationOffline)
            }
        }

        // Reload data sorce
        await NCNetworking.shared.transferDispatcher.notifyAllDelegates { delegate in
            delegate.transferReloadDataSource(serverUrl: metadata.serverUrl, requestData: false, status: nil)
        }
    }
}
