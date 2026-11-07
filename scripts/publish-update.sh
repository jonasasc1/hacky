#!/usr/bin/env bash
# Build a signed release APK and publish it to the `dist` update channel.
# Requires: keystore.properties + keystore present, Android SDK, this repo clone.
# Usage: ./scripts/publish-update.sh <versionCode> [versionName] [notes]
set -euo pipefail
CODE="${1:?Usage: ./scripts/publish-update.sh <versionCode> [versionName] [notes]}"
NAME="${2:-1.$CODE}"
NOTES="${3:-Update v$CODE}"
APK="netaudit-v${CODE}.apk"

echo ">> Baue signierte Release-APK (versionCode=$CODE, versionName=$NAME) ..."
VERSION_CODE="$CODE" VERSION_NAME="$NAME" ./gradlew :app:assembleRelease
cp app/build/outputs/apk/release/app-release.apk "/tmp/$APK"

echo ">> Aktualisiere dist-Branch ..."
WT="$(mktemp -d)"
git worktree add --detach "$WT" >/dev/null
(
  cd "$WT"
  git switch --orphan dist
  cp "/tmp/$APK" "$APK"
  cat > latest.json <<EOF
{
  "versionCode": $CODE,
  "versionName": "$NAME",
  "notes": "$NOTES",
  "apk": "$APK"
}
EOF
  git add "$APK" latest.json
  git commit -qm "dist: NetAudit v$CODE"
  git push -f origin dist
)
git worktree remove --force "$WT"
echo ">> Fertig. Installierte Apps finden v$CODE unter 'App-Update'."
