#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
user_bin="${XDG_BIN_HOME:-$HOME/.local/bin}"
mkdir -p "$user_bin"

if [ -e "$user_bin/reconscope" ] || [ -L "$user_bin/reconscope" ]; then
  existing="$(readlink "$user_bin/reconscope" 2>/dev/null || true)"
  if [ "$existing" = "$repo_dir/reconscope" ]; then
    rm "$user_bin/reconscope"
  else
    echo "Refusing to replace existing path: $user_bin/reconscope" >&2
    exit 1
  fi
fi
ln -s "$repo_dir/reconscope" "$user_bin/reconscope"

case ":${PATH}:" in
  *":$user_bin:"*) path_note="" ;;
  *)
    path_note="export PATH=\"$user_bin:\$PATH\""
    shell_rc="$HOME/.bashrc"
    if [ -f "$shell_rc" ] && ! grep -Fq "$user_bin" "$shell_rc"; then
      printf '\n# ReconScope\n%s\n' "$path_note" >> "$shell_rc"
    fi
    ;;
esac

echo "Installed: $user_bin/reconscope"
if [ -n "${path_note:-}" ]; then
  echo "Run this once in the current terminal: $path_note"
  echo "Then try: reconscope doctor"
else
  echo "Try: reconscope doctor"
fi
