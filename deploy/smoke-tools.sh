#!/bin/sh
# Real call through ~/bin against the registry: last session's diagnosis, so a broken install or token shows at once.
set -eu
"$HOME/bin/desk-trace" --help >/dev/null
"$HOME/bin/desk-trace" last --diagnosis-only | head -3
"$HOME/bin/artifact" --help >/dev/null
echo "smoke ok on $(hostname -s)"
