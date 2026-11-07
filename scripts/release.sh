#!/usr/bin/env bash
# Build a signed release APK locally for a given version code.
# Requires keystore.properties + the keystore present (see README).
# Usage: ./scripts/release.sh <versionCode> [versionName]
set -euo pipefail
CODE="${1:?Usage: ./scripts/release.sh <versionCode> [versionName]}"
NAME="${2:-1.$CODE}"

VERSION_CODE="$CODE" VERSION_NAME="$NAME" ./gradlew :app:assembleRelease
cp app/build/outputs/apk/release/app-release.apk "netaudit-v${CODE}.apk"

echo
echo "Gebaut: netaudit-v${CODE}.apk (versionCode=$CODE, versionName=$NAME)"
echo "Release veröffentlichen (GitHub CLI, lokal authentifiziert):"
echo "  gh release create v${CODE} netaudit-v${CODE}.apk --generate-notes"
echo "Oder manuell: auf GitHub ein Release mit Tag 'v${CODE}' anlegen und die APK anhängen."
