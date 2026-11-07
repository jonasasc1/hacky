# NetAudit

Ein **Netzwerk-Audit-Tool für Android** für autorisiertes Testen: Host-Erkennung,
TCP-Port-Scan und Dienst-Erkennung in Netzwerken, **die dir gehören oder für die du
eine ausdrückliche Erlaubnis hast**.

> ⚠️ **Nur für autorisiertes Testen.** Das Scannen oder der Zugriff auf fremde
> Systeme ohne Erlaubnis ist in den meisten Ländern strafbar (u. a. Österreich
> §118a/§119/§119a StGB, Deutschland §202a–c StGB). Die Verantwortung liegt bei dir.
> Die App zeigt beim ersten Start einen Zustimmungs-Screen.

## Funktionen

- **Netzwerk-Info**: SSID, eigene IPv4 + Präfix, Gateway, errechnete Scan-Range.
- **Host-Discovery**: Ping-Sweep (`InetAddress.isReachable`) + TCP-Knock auf gängige
  Ports + ARP-Tabelle (`/proc/net/arp`, soweit vom OS erlaubt). Hostnamen per
  Reverse-DNS. Subnetze > /24 werden auf das eigene /24 begrenzt.
- **MAC-Vendor-Lookup**: Offline-Herstellererkennung über die gebündelte
  IEEE-OUI-Datenbank (`assets/oui.txt`, ~40 000 Einträge aus der Wireshark-
  „manuf"-Registry). Keine Internet-Abfrage nötig.
- **Port-Scan pro Host**: TCP-Connect-Scan über *gängige Ports* oder einen
  frei wählbaren *Bereich* (bis 20 000 Ports). Banner-Grab (HTTP `HEAD`, rohe
  Service-Banner) und Dienst-Zuordnung nach Portnummer.
- **Dienst-Erkennung (mDNS/DNS-SD + SSDP/UPnP)**: findet Geräte, die auf
  Ping/Port-Scan nicht reagieren – Drucker, Chromecast, AirPlay, HomeKit, SMB,
  Router, Smart-TVs, NAS, IoT. Eigener mDNS-Parser (keine Fremd-Bibliothek),
  SSDP per `M-SEARCH`-Multicast, mit Wi-Fi-Multicast-Lock.
- **Export**: Host-Liste und Port-Scan-Ergebnisse als **CSV** oder **JSON**
  über den Android-Dateidialog (Storage Access Framework, keine Speicher-
  Berechtigung nötig).
- **Vollständiger Audit (One-Button)**: Host-Discovery → mDNS/SSDP → Port-Scan →
  Security-Probes in einem Durchlauf, mit Live-Findings nach Schweregrad und
  HTML-/CSV-/JSON-Report.
- **Security-Findings (read-only, keine Brute-Force)**: unverschlüsseltes HTTP,
  Basic-Auth über HTTP, Telnet/FTP-Klartext, veraltetes/abgelaufenes/selbst-
  signiertes TLS, fehlendes HSTS, offenes Redis/Elasticsearch, VNC ohne Auth,
  SNMP-Default-Community „public", **SMBv1** aktiv, Default-Credential-Hinweise.
- **UDP-Scan**: DNS (inkl. offener-Resolver-Erkennung), NTP, NetBIOS.
- **Scan-Verlauf + Diff**: jeder Audit wird gespeichert; nach dem Scan zeigt die
  App „was ist neu im Netz" (neue/verschwundene Hosts, neue Ports, neue Findings).
- **Traffic-Monitor (Beta, VpnService)**: lokaler Mitschnitt **nur des eigenen
  Geräts** – zeigt pro Verbindung Klartext-HTTP (mit Host/URL) vs. TLS (mit SNI)
  und DNS-Namen. Sieht keine fremden Geräte (auf Android ohne Root nicht möglich).

### Was die App bewusst NICHT tut
Sie schneidet **keinen fremden Datenverkehr** mit. Auf nicht gerooteten Android-Geräten
kann eine App den Traffic anderer Geräte technisch nicht abgreifen (ginge nur mit
Root/MITM). NetAudit macht ausschließlich **aktives** Auditing des eigenen Netzes.

## Bauen

Voraussetzungen: JDK 17+, Android SDK (Platform 34, Build-Tools 34.0.0).

```bash
# SDK-Pfad setzen (einmalig)
echo "sdk.dir=/pfad/zum/Android/sdk" > local.properties

# Debug-APK bauen
./gradlew :app:assembleDebug
# -> app/build/outputs/apk/debug/app-debug.apk
```

In **Android Studio**: Projekt öffnen → *Run* oder *Build > Build APK(s)*.

### Signierte Release-APK

Das Projekt signiert den Release-Build automatisch, **wenn** eine Datei
`keystore.properties` im Projekt-Root liegt (sie ist bewusst in `.gitignore`,
damit Keystore und Passwörter **nie** ins Git geraten). Format:

```properties
storeFile=netaudit-release.jks
storePassword=DEIN_STORE_PASSWORT
keyAlias=netaudit
keyPassword=DEIN_KEY_PASSWORT
```

Keystore einmalig selbst erzeugen (empfohlen für echte Nutzung):

```bash
keytool -genkeypair -v -keystore netaudit-release.jks -alias netaudit \
  -keyalg RSA -keysize 2048 -validity 10000
```

Dann:

```bash
./gradlew :app:assembleRelease
# -> app/build/outputs/apk/release/app-release.apk
```

Ohne `keystore.properties` wird der Release-Build **unsigniert** erzeugt
(CI-tauglich). **Bewahre den Keystore sicher auf** – geht er verloren, kannst
du keine App-Updates mehr unter derselben Signatur veröffentlichen.

## App-Update (Self-Update über die Repo-Datei)

Die App aktualisiert sich selbst (Screen **„App-Update"** im Hauptmenü): sie liest
`latest.json` aus dem Branch **`dist`** über `raw.githubusercontent.com`,
vergleicht `versionCode` mit der installierten Version und lädt bei Bedarf die
dort referenzierte APK herunter und installiert sie – **ohne GitHub-Release,
ohne Token, ohne CI-Secret**.

**Voraussetzungen**
- Das Repository ist **öffentlich** (privat würde einen Token in der App
  erfordern – bewusst nicht eingebaut).
- Jede verteilte APK ist mit **demselben Keystore** signiert wie die installierte
  App (sonst verweigert Android das Update).

**Manifest** (`dist/latest.json`):

```json
{ "versionCode": 2, "versionName": "1.1", "notes": "…", "apk": "netaudit-v2.apk" }
```

### Neue Version veröffentlichen

Alles per `git push` – kein Zugriff auf GitHub-Weboberfläche nötig:

```bash
./scripts/publish-update.sh 3 1.2    # baut signierte APK (versionCode 3) und
                                     # aktualisiert den dist-Branch (APK + latest.json)
```

Danach findet jede installierte App die neue Version unter „App-Update".
Der `dist`-Branch ist ein eigenständiger (orphan) Branch, der bei jedem Release
neu geschrieben wird – die Haupt-Historie bleibt frei von APK-Binärdateien.

## Installieren

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Oder die `app-debug.apk` aufs Telefon kopieren und über den Dateimanager
installieren (Installation aus unbekannten Quellen erlauben).

- **min SDK**: 26 (Android 8.0)  •  **target SDK**: 34
- Die Debug-APK ist mit dem Android-Debug-Keystore signiert — ideal zum Testen,
  für eine Veröffentlichung im Play Store brauchst du einen eigenen Release-Key.

## Berechtigungen

| Berechtigung | Zweck |
|---|---|
| `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE` | Scannen & Netzwerk-Info |
| `ACCESS_FINE_LOCATION` | Nur um die aktuelle WLAN-SSID anzuzeigen (Android-Vorgabe seit 8.1) |

## Architektur

| Datei | Aufgabe |
|---|---|
| `ConsentActivity` | Einmaliger Zustimmungs-Screen |
| `MainActivity` | Netzwerk-Info + Host-Discovery-Liste + Export |
| `PortScanActivity` | Port-Scan für einen gewählten Host + Export |
| `DiscoveryActivity` | mDNS/DNS-SD- und SSDP/UPnP-Dienst-Erkennung |
| `NetworkUtils` | WLAN-Info, Subnetz-Berechnung, Host-Discovery (Coroutines) |
| `PortScanner` | TCP-Connect-Scan, Banner-Grab, Dienst-Map |
| `ServiceDiscovery` | mDNS-Query/-Parser + SSDP-`M-SEARCH`, Multicast-Lock |
| `OuiLookup` | Offline-MAC-Vendor-Lookup aus `assets/oui.txt` |
| `Exporter` | CSV-/JSON-Serialisierung der Ergebnisse |

Reines Kotlin + Android Views (Material 3), Nebenläufigkeit über Kotlin-Coroutines
(begrenzte Parallelität via `Semaphore`). Keine Drittanbieter-Scan-Bibliotheken.
