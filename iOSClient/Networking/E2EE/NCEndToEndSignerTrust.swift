// SPDX-FileCopyrightText: 2026 rima Pflege GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

import CryptoKit
import Foundation
import UIKit

enum NCEndToEndSignerTrust {
    /// Hash the actual SubjectPublicKeyInfo, not renewable certificate fields.
    static func fingerprint(certificate: String) -> String? {
        guard let pem = NCEndToEndEncryption().extractPublicKey(fromCertificate: certificate) else { return nil }
        let body = pem.components(separatedBy: .newlines).filter { !$0.hasPrefix("-----") }.joined()
        guard let der = Data(base64Encoded: body), !der.isEmpty else { return nil }
        return SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    static func certificates(account: String, rootID: String) -> [String] {
        guard !account.isEmpty, !rootID.isEmpty else { return [] }
        return (try? NCPreferences().getEndToEndApprovedSigners(account: account, rootID: rootID)) ?? []
    }

    /// The decision must come from an explicit, independently compared fingerprint.
    @MainActor
    static func recordDecision(_ approved: Bool, account: String, rootID: String, certificate: String) -> Bool {
        guard approved, !account.isEmpty, !rootID.isEmpty, let fingerprint = fingerprint(certificate: certificate) else { return false }
        let preferences = NCPreferences()
        do {
            var accepted = try preferences.getEndToEndApprovedSigners(account: account, rootID: rootID)
            if !accepted.contains(where: { self.fingerprint(certificate: $0) == fingerprint }) {
                accepted.append(certificate)
                try preferences.setEndToEndApprovedSigners(accepted, account: account, rootID: rootID)
            }
            return true
        } catch {
            return false
        }
    }

    @MainActor private static var presenting = false

    @MainActor
    static func confirm(account: String, rootID: String, claimedUserID: String, certificate: String) async -> Bool {
#if EXTENSION
        return false // Extensions cannot ask for an independent fingerprint comparison.
#else
        guard !presenting, !Task.isCancelled, !rootID.isEmpty,
              let fingerprint = fingerprint(certificate: certificate),
              UIApplication.shared.applicationState == .active,
              NCSession.shared.getSession(controller: nil).account == account,
              let window = UIApplication.shared.mainAppWindow,
              var presenter = window.rootViewController else { return false }
        while let presented = presenter.presentedViewController { presenter = presented }
        guard presenter.viewIfLoaded?.window != nil, !presenter.isBeingDismissed else { return false }

        presenting = true
        defer { presenting = false }
        let session = NCSession.shared.getSession(account: account)
        let folder = NCManageDatabase.shared.getMetadata(predicate: NSPredicate(format: "account == %@ AND ocId == %@", account, rootID))?.fileNameView ?? rootID
        let context = [session.urlBase, session.userId, folder, claimedUserID]
            .map { displayLabel($0) }.joined(separator: "\n")
        let message = NSLocalizedString("_e2ee_fingerprint_compare_", comment: "") + "\n\n" + context + "\n\nSHA-256\n" + fingerprint
        let prompt = FingerprintPrompt(message: message)
        let approved = await prompt.present(from: presenter)
        guard !Task.isCancelled, UIApplication.shared.applicationState == .active,
              NCSession.shared.getSession(controller: nil).account == account else { return false }
        return recordDecision(approved, account: account, rootID: rootID, certificate: certificate)
#endif
    }

    private static func displayLabel(_ value: String) -> String {
        String(value.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) && $0.properties.generalCategory != .format })
    }

#if !EXTENSION
    /// Leaving the foreground cancels the request rather than retaining a stale approval.
    @MainActor private final class FingerprintPrompt {
        private let alert: UIAlertController
        private var continuation: CheckedContinuation<Bool, Never>?
        private var observer: NSObjectProtocol?

        init(message: String) {
            alert = UIAlertController(title: NSLocalizedString("_e2ee_fingerprint_verify_", comment: ""), message: message, preferredStyle: .alert)
        }

        func present(from presenter: UIViewController) async -> Bool {
            await withCheckedContinuation { continuation in
                self.continuation = continuation
                alert.addAction(UIAlertAction(title: NSLocalizedString("_cancel_", comment: ""), style: .cancel) { [weak self] _ in
                    self?.finish(false)
                })
                alert.addAction(UIAlertAction(title: NSLocalizedString("_e2ee_fingerprint_matches_", comment: ""), style: .default) { [weak self] _ in
                    self?.finish(true)
                })
                observer = NotificationCenter.default.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
                    Task { @MainActor in self?.finish(false) }
                }
                presenter.present(alert, animated: true)
            }
        }

        private func finish(_ approved: Bool) {
            guard let continuation else { return }
            self.continuation = nil
            if let observer { NotificationCenter.default.removeObserver(observer) }
            observer = nil
            alert.dismiss(animated: true)
            continuation.resume(returning: approved)
        }
    }
#endif
}
