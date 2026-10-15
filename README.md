<!--
SPDX-FileCopyrightText: Nextcloud GmbH
SPDX-FileCopyrightText: 2026 rima Pflege GmbH
SPDX-License-Identifier: GPL-3.0-or-later
-->

# rima.Cloud · iPhone

Angepasster iPhone-Client der rima Pflege GmbH auf Grundlage der
[offiziellen Nextcloud-iOS-App](https://github.com/nextcloud/ios).

Dieser Quellstand gehört zu **Version 1.0.0, Build 26**. Er basiert auf
Nextcloud iOS **35.1.0**, Commit
`dc214c4c92125da009bf9581b83462d4ba36d5fb`.

## Anpassungen

- Name rima.Cloud, eigene Wolkengrafik und Petrol als Markenfarbe.
- Voreingestellter Server `https://cloud.rima-pflege.de`.
- Quellcode-Link in den App-Einstellungen zu `rima-richard/rima.Cloud_open`.
- Vereinfachte Dateiansicht mit Suche, Dateien/Mehr und separatem Plus.
- Kurzer Start mit opaler Wolkenanimation.
- Ausschließlich iPhone; keine iPad-, Mac- oder Vision-Pro-Veröffentlichung.
- Nextcloud-Dateifunktionen, PDF-Vorschau, Upload/Download, Offline-Dateien,
  Scannen, Teilen-Erweiterung und iOS-Dateianbieter bleiben erhalten.
- Firebase entfernt; HTTPS-Voreinstellung und Berechtigungsabfragen auf
  die verwendeten Funktionen begrenzt.

## Bauen

Die genaue Anleitung steht in [RIMA-Release.txt](RIMA-Release.txt).
Benötigt werden Xcode 27 und die iOS-SDKs. Öffne `Nextcloud.xcodeproj`,
wähle das Schema `rima.Cloud` und löse die Swift-Pakete anhand des
mitgelieferten `Package.resolved` auf. Für Geräte-Builds benötigst du
Dein eigenes Apple-Developer-Team und passende Bundle-IDs/App-Gruppen.
`GoogleService-Info.plist` ist für diese Variante nicht erforderlich.

Die Bibliotheken werden von SwiftPM in den festgehaltenen Revisionen
bezogen. Signierschlüssel, Profile, Kennwörter und Unternehmensdateien
sind kein Bestandteil dieses Repositories.

## Quellcode und Lizenz

Der Programmcode steht unter [GPL-3.0-or-later](LICENSE.txt) mit der
übernommenen [Apple-App-Store-Ausnahme](COPYING.iOS). Weitere Hinweise
stehen in `LICENSES/`, `REUSE.toml` und den Danksagungen der App.
Marken und Grafiken behalten ihre gesonderten Rechtehinweise.

Der Tag `v1.0.0-build26` bezeichnet den zu Build26 gehörenden Quellstand.
GitHub stellt über **Code → Download ZIP** auch ein Quellarchiv bereit.
Die Website-Service-Seite kann auf dieses Repository bzw. den passenden
Release-Tag verweisen. Ein App-Installationslink wird hier nicht beworben.

## Stand der Bereitstellung

Build26 ersetzt den bisherigen Upstream-Link in den App-Einstellungen
durch dieses Quellcode-Repository. Er wurde lokal im Simulator geprüft,
archiviert und signiert exportiert; bei Apple wurde er nicht hochgeladen.
Build25 wurde zuvor im Simulator geprüft, auf
dem iPhone17Pro installiert und bei App Store Connect hochgeladen.
Die App ist noch nicht zur App-Prüfung eingereicht und nicht veröffentlicht. Unlisted-Verteilung
ist vorgesehen. Das Repository bleibt bis zur Freigabe durch den
Projektinhaber privat; vor der Einreichung muss der Quellcode für die
App-Empfänger erreichbar sein.

## Übernommene Projektinformationen

Das ursprüngliche README bleibt als [UPSTREAM-README.md](UPSTREAM-README.md)
erhalten. Die Nextcloud-CI-Dateien liegen als unveränderte Referenz in
`upstream-ci/`; sie werden in diesem Repository nicht automatisch ausgeführt.
GitHub Actions ist für die initiale private Bereitstellung deaktiviert.
