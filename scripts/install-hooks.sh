#!/usr/bin/env bash
# Instala los git hooks versionados del repo apuntando core.hooksPath a
# scripts/hooks. Ejecútalo una vez por clon:  bash scripts/install-hooks.sh
set -eu
root="$(git rev-parse --show-toplevel)"
git -C "$root" config core.hooksPath scripts/hooks
chmod +x "$root/scripts/hooks/"* 2>/dev/null || true
echo "Hooks instalados: core.hooksPath=scripts/hooks"
echo "Gate pre-commit activo (tests de lógica pura con g++ + higiene de artefactos)."
