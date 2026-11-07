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
- **Port-Scan pro Host**: TCP-Connect-Scan über *gängige Ports* oder einen
  frei wählbaren *Bereich* (bis 20 000 Ports). Banner-Grab (HTTP `HEAD`, rohe
  Service-Banner) und Dienst-Zuordnung nach Portnummer.

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
| `MainActivity` | Netzwerk-Info + Host-Discovery-Liste |
| `PortScanActivity` | Port-Scan für einen gewählten Host |
| `NetworkUtils` | WLAN-Info, Subnetz-Berechnung, Host-Discovery (Coroutines) |
| `PortScanner` | TCP-Connect-Scan, Banner-Grab, Dienst-Map |

Reines Kotlin + Android Views (Material 3), Nebenläufigkeit über Kotlin-Coroutines
(begrenzte Parallelität via `Semaphore`). Keine Drittanbieter-Scan-Bibliotheken.
