#!/bin/sh
# Installs the registry's command line tools for this host: a stable checkout plus symlinks in ~/bin. Safe to rerun.
# ~/bin/desk-trace works as a copy too, should a host sync dereference the link. Ends with the smoke test.
set -eu
DIR="${ARTIFACT_REGISTRY_DIR:-$HOME/.local/share/artifact-registry}"
if [ -d "$DIR/.git" ]; then git -C "$DIR" pull -q --ff-only; else git clone -q https://github.com/fstandhartinger/artifact-registry.git "$DIR"; fi
for tool in desk-trace artifact; do ln -sfn "$DIR/bin/$tool" "$HOME/bin/$tool"; done
exec sh "$DIR/deploy/smoke-tools.sh"
