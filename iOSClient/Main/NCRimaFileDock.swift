// SPDX-FileCopyrightText: Nextcloud GmbH
// SPDX-FileCopyrightText: 2026 rima Pflege GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

import UIKit

final class NCRimaFileDock: UIView {
    let navigationCapsule = UIVisualEffectView()
    let filesButton = UIButton(type: .system)
    let moreButton = UIButton(type: .system)
    private let onSelect: (Int) -> Void

    @available(iOS 26.0, *)
    init(addButton: UIButton, onSelect: @escaping (Int) -> Void) {
        self.onSelect = onSelect
        super.init(frame: .zero)
        translatesAutoresizingMaskIntoConstraints = false
        accessibilityIdentifier = "fileDock"

        let glass = UIGlassEffect(style: .regular)
        glass.isInteractive = true
        navigationCapsule.effect = glass
        navigationCapsule.layer.cornerRadius = 32
        navigationCapsule.clipsToBounds = true
        navigationCapsule.translatesAutoresizingMaskIntoConstraints = false
        addSubview(navigationCapsule)

        for (index, button) in [filesButton, moreButton].enumerated() {
            button.translatesAutoresizingMaskIntoConstraints = false
            button.configuration = .plain()
            button.configuration?.preferredSymbolConfigurationForImage = UIImage.SymbolConfiguration(pointSize: 23, weight: .regular)
            button.accessibilityIdentifier = index == 0 ? "filesTab" : "moreTab"
            button.accessibilityLabel = NSLocalizedString(index == 0 ? "_home_" : "_more_", comment: "")
            button.addAction(UIAction { [weak self] _ in self?.onSelect(index) }, for: .touchUpInside)
            navigationCapsule.contentView.addSubview(button)
        }

        addSubview(addButton)
        NSLayoutConstraint.activate([
            heightAnchor.constraint(equalToConstant: 64),
            navigationCapsule.leadingAnchor.constraint(equalTo: leadingAnchor),
            navigationCapsule.topAnchor.constraint(equalTo: topAnchor),
            navigationCapsule.bottomAnchor.constraint(equalTo: bottomAnchor),
            navigationCapsule.widthAnchor.constraint(equalToConstant: 128),
            filesButton.leadingAnchor.constraint(equalTo: navigationCapsule.contentView.leadingAnchor, constant: 4),
            filesButton.centerYAnchor.constraint(equalTo: centerYAnchor),
            filesButton.widthAnchor.constraint(equalToConstant: 56),
            filesButton.heightAnchor.constraint(equalToConstant: 56),
            moreButton.trailingAnchor.constraint(equalTo: navigationCapsule.contentView.trailingAnchor, constant: -4),
            moreButton.centerYAnchor.constraint(equalTo: centerYAnchor),
            moreButton.widthAnchor.constraint(equalToConstant: 56),
            moreButton.heightAnchor.constraint(equalToConstant: 56),
            addButton.trailingAnchor.constraint(equalTo: trailingAnchor),
            addButton.centerYAnchor.constraint(equalTo: centerYAnchor)
        ])
    }

    required init?(coder: NSCoder) { return nil }

    func update(selectedIndex: Int, tintColor: UIColor) {
        for (index, button) in [filesButton, moreButton].enumerated() {
            let selected = index == selectedIndex
            let symbol = index == 0 ? (selected ? "folder.fill" : "folder") : (selected ? "ellipsis.circle.fill" : "ellipsis.circle")
            button.configuration?.image = UIImage(systemName: symbol)
            button.configuration?.baseForegroundColor = selected ? tintColor : .label
            button.accessibilityTraits = selected ? [.button, .selected] : [.button]
        }
    }
}
