// SPDX-FileCopyrightText: Nextcloud GmbH
// SPDX-FileCopyrightText: 2026 rima Pflege GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

import UIKit

final class NCRimaLaunchOverlay: UIView {
    private let cloud = UIImageView(image: UIImage(named: "rima-launch-cloud.png"))

    init() {
        super.init(frame: .zero)
        backgroundColor = .clear
        accessibilityElementsHidden = true
        let background = UIVisualEffectView(effect: UIBlurEffect(style: .systemUltraThinMaterialLight))
        background.contentView.backgroundColor = UIColor.white.withAlphaComponent(0.18)
        background.translatesAutoresizingMaskIntoConstraints = false
        cloud.contentMode = .scaleAspectFit
        cloud.translatesAutoresizingMaskIntoConstraints = false
        addSubview(background)
        addSubview(cloud)
        NSLayoutConstraint.activate([
            background.leadingAnchor.constraint(equalTo: leadingAnchor),
            background.trailingAnchor.constraint(equalTo: trailingAnchor),
            background.topAnchor.constraint(equalTo: topAnchor),
            background.bottomAnchor.constraint(equalTo: bottomAnchor),
            cloud.widthAnchor.constraint(equalToConstant: 256),
            cloud.heightAnchor.constraint(equalToConstant: 256),
            cloud.centerXAnchor.constraint(equalTo: safeAreaLayoutGuide.centerXAnchor),
            cloud.centerYAnchor.constraint(equalTo: safeAreaLayoutGuide.centerYAnchor)
        ])
    }

    required init?(coder: NSCoder) { return nil }

    func animateAndDismiss() {
        guard !UIAccessibility.isReduceMotionEnabled else {
            removeFromSuperview()
            return
        }
        cloud.transform = CGAffineTransform(scaleX: 0.98, y: 0.98)
        UIView.animate(withDuration: 0.3, delay: 0, options: [.curveEaseOut]) {
            self.cloud.transform = .identity
        }
        UIView.animate(withDuration: 0.2, delay: 0.3, options: [.curveEaseOut]) {
            self.alpha = 0
        } completion: { _ in
            self.removeFromSuperview()
        }
    }
}
