// SPDX-FileCopyrightText: Nextcloud GmbH
// SPDX-FileCopyrightText: 2026 rima Pflege GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

import Testing
import UIKit
@testable import Nextcloud

@Suite("rima.Cloud file navigation", .serialized)
@MainActor
struct NCRimaNavigationTests {
    private func makeController() throws -> NCMainTabBarController {
        let controller = try #require(UIStoryboard(name: "Main", bundle: nil)
            .instantiateInitialViewController() as? NCMainTabBarController)
        controller.loadViewIfNeeded()
        return controller
    }

    @Test("Files and More are the only tabs")
    func fileFocusedTabs() throws {
        let controller = try makeController()
        let navigation = try #require(controller.viewControllers?.first as? NCFilesNavigationController)
        #expect(controller.viewControllers?.count == 2)
        #expect(navigation.topViewController is NCFiles)
        #expect(controller.viewControllers?.last is NCMoreNavigationController)
        #expect(controller.selectedIndex == 0)
    }

    @Test("Old file shortcuts return to Files instead of a removed tab", arguments: [DeepLink.openFiles, .openFavorites, .openMedia])
    func legacyFileShortcuts(_ link: DeepLink) throws {
        let controller = try makeController()
        controller.selectedIndex = 1
        NCDeepLinkHandler().handleDeepLink(link, controller: controller)
        #expect(controller.currentViewController() is NCFiles)
    }

    @Test("Settings shortcut selects the surviving More tab")
    func settingsShortcut() async throws {
        let controller = try makeController()
        NCDeepLinkHandler().handleDeepLink(.openSettings, controller: controller)
        #expect(controller.selectedViewController is NCMoreNavigationController)
        await Task.yield()
    }

    @Test("Only the root file title is empty; folder names remain")
    func folderTitles() throws {
        let controller = try makeController()
        let root = try #require(controller.currentViewController() as? NCFiles)
        root.loadViewIfNeeded()
        #expect(root.titleCurrentFolder.isEmpty)
        #expect(root.getNavigationTitle().isEmpty)
        #expect((root.navigationItem.titleView as? NCRimaSearchTitleView)?.searchBar === root.searchController?.searchBar)
        #expect(root.navigationItem.searchController == nil)

        let folder = try #require(UIStoryboard(name: "NCFiles", bundle: nil)
            .instantiateInitialViewController() as? NCFiles)
        folder.serverUrl = "https://example.invalid/remote.php/dav/files/test/Documents"
        folder.titleCurrentFolder = "Documents"
        folder.loadViewIfNeeded()
        #expect(folder.titleCurrentFolder == "Documents")
    }

    @Test("The separate add action follows the Files tab, search and selection")
    func dockedAddActionVisibility() throws {
        guard #available(iOS 26.0, *), UIDevice.current.userInterfaceIdiom == .phone else { return }
        let controller = try makeController()
        let navigation = try #require(controller.currentNavigationController() as? NCFilesNavigationController)
        navigation.loadViewIfNeeded()
        controller.view.frame = CGRect(x: 0, y: 0, width: 402, height: 874)
        controller.view.layoutIfNeeded()
        let button = navigation.menuPlusButton
        let dock = try #require(button.superview as? NCRimaFileDock)
        #expect(dock.superview === controller.view)
        #expect(dock.navigationCapsule.frame.minX == 0)
        #expect(dock.filesButton.title(for: .normal) == nil)
        #expect(dock.moreButton.title(for: .normal) == nil)
        #expect(!button.isHidden)
        #expect(button.showsMenuAsPrimaryAction)
        #expect(controller.viewControllers?.count == 2)
        #expect(abs(button.frame.midY - dock.navigationCapsule.frame.midY) < 0.5)
        #expect(dock.frame.minX == controller.view.safeAreaInsets.left + 16)

        controller.selectedIndex = 1
        controller.view.setNeedsLayout()
        controller.view.layoutIfNeeded()
        #expect(button.isHidden)
        controller.selectedIndex = 0
        controller.view.setNeedsLayout()
        controller.view.layoutIfNeeded()
        #expect(!button.isHidden)

        let menu = try #require(navigation.menuPlus)
        menu.hiddenPlusButton(isEditMode: true, isSearchingMode: false, animation: false)
        #expect(button.alpha == 0)
        menu.hiddenPlusButton(isEditMode: false, isSearchingMode: true, animation: false)
        #expect(button.alpha == 0)
        menu.hiddenPlusButton(isEditMode: false, isSearchingMode: false, animation: false)
        #expect(button.alpha == 1)
        #expect(controller.isTabBarHidden)
        controller.hide()
        #expect(dock.isHidden)
        controller.show()
        #expect(!dock.isHidden)
        #expect(controller.isTabBarHidden)
    }


    @Test("Cancel restores Files even when search is embedded in the title view")
    func cancelCenteredSearch() throws {
        let controller = try makeController()
        let files = try #require(controller.currentViewController() as? NCFiles)
        files.loadViewIfNeeded()
        let searchBar = try #require(files.searchController?.searchBar)
        files.searchBarTextDidBeginEditing(searchBar)
        #expect(files.isSearchingMode)
        files.searchResultText = "pending search"
        files.searchBarCancelButtonClicked(searchBar)
        #expect(!files.isSearchingMode)
        #expect(files.searchResultText == nil)
        #expect(searchBar.text?.isEmpty != false)
    }


    @Test("The first iOS launch image contains a visible cloud")
    func launchScreenCloud() throws {
        #expect(Bundle.main.url(forResource: "rima-launch-cloud", withExtension: "png") != nil)
        let launch = try #require(UIStoryboard(name: "RimaCloudLaunchScreen", bundle: nil).instantiateInitialViewController())
        launch.loadViewIfNeeded()
        launch.view.frame = CGRect(x: 0, y: 0, width: 402, height: 874)
        launch.view.layoutIfNeeded()
        let cloud = try #require(launch.view.subviews.compactMap { $0 as? UIImageView }.first)
        #expect(cloud.image != nil)
        #expect(cloud.bounds.width == 256)
        #expect(cloud.bounds.height == 256)
        let preview = UIGraphicsImageRenderer(bounds: launch.view.bounds).image { context in
            launch.view.layer.render(in: context.cgContext)
        }
        if let data = preview.pngData() { Attachment.record(data, named: "rima.Cloud-Launchscreen.png") }
    }

}
