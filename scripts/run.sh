#!/bin/sh
set -eu
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$PROJECT_DIR"
if [ ! -f target/net-view-0.5.0.jar ]; then
  ./scripts/build.sh
fi
exec java --enable-native-access=ALL-UNNAMED -Djavafx.cachedir="$PROJECT_DIR/.cache/javafx" \
  -Dnetview.projectDir="$PROJECT_DIR" -jar target/net-view-0.5.0.jar "$@"
