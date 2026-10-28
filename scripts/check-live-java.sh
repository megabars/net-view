#!/bin/sh
set -eu
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$PROJECT_DIR"
if [ ! -f target/net-view-0.5.0.jar ]; then
  ./scripts/build.sh
fi
printf '%s\n' 'Authenticate for native tcpdump in this Terminal; Java and the lab keep your normal user permissions.'
/usr/bin/sudo -v
exec python3 tools/check_live_capture_java.py "$@"
