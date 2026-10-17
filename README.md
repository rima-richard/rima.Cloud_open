<!--
SPDX-FileCopyrightText: Nextcloud GmbH
SPDX-FileCopyrightText: 2026 rima Pflege GmbH
SPDX-License-Identifier: GPL-3.0-or-later
-->

# rima.Cloud · iPhone

Angepasster iPhone-Client der rima Pflege GmbH auf Grundlage der
[offiziellen Nextcloud-iOS-App](https://github.com/nextcloud/ios).

Dieser Quellstand gehört zu **Version 1.0.0, Build 27**. Er basiert auf
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

Der Tag `v1.0.0-build27` bezeichnet den zu Build27 gehörenden Quellstand.
GitHub stellt über **Code → Download ZIP** auch ein Quellarchiv bereit.
Die Website-Service-Seite kann auf dieses Repository bzw. den passenden
Release-Tag verweisen. Ein App-Installationslink wird hier nicht beworben.

## Technischer Quellstand

Build27 enthält Sicherheitskorrekturen für E2EE-Authentifizierung,
Empfängerzustand und Replay-Zähler, sichere Dokumentexporte und
Teilen-Dateinamen sowie bereinigte Login-Protokolle. Bei erstmals geöffneten
E2EE-Freigaben eines unbekannten Schlüssels ist ein Fingerabdruck-Abgleich
über einen unabhängigen Kanal erforderlich. Der eigene Fingerabdruck ist
in den E2EE-Einstellungen sichtbar. Normale Cloud-Ordner benötigen diesen
Abgleich nicht. Die Bestätigung gilt nur für das Konto und den verschlüsselten
Stammordner; lokale E2EE-Entfernung löscht auch diese Bestätigungen.

Der Simulator-Build und 153 lokale Unit-Tests in 20 Testsuiten wurden
in der Entwicklungsprüfung dieses Quellstands erfolgreich geprüft.
Der Stilcheck der geänderten Swift-Dateien ist bestanden. Die enthaltenen
Kryptografie-Testschlüssel sind ausschließlich synthetische Testdaten
und dürfen niemals produktiv verwendet werden.

### Quellstand und App-Store-Status

Die früheren Angaben zum Upload von Build25 und zum in der damaligen
Entwicklungsprüfung nicht ausgeführten Upload von Build27 beschreiben
historische Prüfschritte. Sie sind keine aktuelle Statusanzeige für
App Store Connect.

Der Tag `v1.0.0-build27` bezeichnet einen veröffentlichten Quellstand.
Weder dieser Tag noch die lokalen Testergebnisse bestätigen, welcher Build
aktuell bei Apple zugeordnet, eingereicht, genehmigt oder veröffentlicht ist.
Maßgeblich für diese Fragen ist der aktuelle Eintrag in App Store Connect.
Die archivierten Build-Tags bleiben unverändert; aktuelle redaktionelle
Klarstellungen stehen im README des Hauptzweigs.

[Support, Quellcode und Lizenzen](https://rima-pflege.de/apps-lizenzen#rima-cloud)
sowie die [Cloud-Datenschutzhinweise](https://rima-pflege.de/datenschutz#rima-cloud)
sind öffentlich erreichbar. Die Veröffentlichung des Quellcodes ist von
der App-Verteilung getrennt. Ein späterer Unlisted-Installationslink wird
von rima intern verteilt.

Das Quellcode-Repository `rima-richard/rima.Cloud_open` ist seit dem
16.10.2026 auf Freigabe des Projektinhabers öffentlich erreichbar.
Das Arbeitsrepository `rima-richard/rima.Cloud` bleibt privat.

## Übernommene Projektinformationen

Das ursprüngliche README bleibt als [UPSTREAM-README.md](UPSTREAM-README.md)
erhalten. Die Nextcloud-CI-Dateien liegen als unveränderte Referenz in
`upstream-ci/`; sie werden in diesem Repository nicht automatisch ausgeführt.
GitHub Actions bleibt in beiden Repositories deaktiviert.
