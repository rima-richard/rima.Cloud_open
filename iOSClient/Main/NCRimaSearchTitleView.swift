// SPDX-FileCopyrightText: Nextcloud GmbH
// SPDX-FileCopyrightText: 2026 rima Pflege GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

import UIKit

final class NCRimaSearchTitleView: UIView {
    let searchBar: UISearchBar

    init(searchBar: UISearchBar) {
        self.searchBar = searchBar
        super.init(frame: CGRect(x: 0, y: 0, width: 280, height: 44))
        addSubview(searchBar)
    }

    required init?(coder: NSCoder) { return nil }

    override var intrinsicContentSize: CGSize { CGSize(width: 280, height: 44) }

    override func layoutSubviews() {
        super.layoutSubviews()
        guard searchBar.superview === self else { return }
        searchBar.frame = bounds
        searchBar.layoutIfNeeded()
        let fieldFrame = searchBar.searchTextField.convert(searchBar.searchTextField.bounds, to: self)
        searchBar.frame = bounds.offsetBy(dx: 0, dy: bounds.midY - fieldFrame.midY)
    }
}
