#!/usr/bin/env bash
# Sharingan banner — shown at the start of triage.sh and /analyze-sample.
# Colors only when stdout is a real terminal (so it never pollutes logs/pipes).

O=$'\033[38;5;208m'   # orange (Claude-style accent)
A=$'\033[38;5;214m'   # amber
R=$'\033[38;5;196m'   # Sharingan red
D=$'\033[38;5;244m'   # dim grey
B=$'\033[1m'; X=$'\033[0m'
if [ ! -t 1 ] || [ -n "$NO_COLOR" ]; then O=""; A=""; R=""; D=""; B=""; X=""; fi

printf '\n'

# --- Sharingan eye (red) ---
printf '%s' "$R$B"
cat <<'EYE'
            .-"""""-.
          .'  ,   ,  '.
         /    ( ◉ )    \
         \     '   '    /
          '.__       __.'
             '-.....-'
EYE
printf '%s' "$X"
printf '\n'

# --- SHARINGAN wordmark (orange) ---
printf '%s' "$O$B"
cat <<'ART'
 ____  _   _    _    ____  ___ _   _  ____    _    _   _
/ ___|| | | |  / \  |  _ \|_ _| \ | |/ ___|  / \  | \ | |
\___ \| |_| | / _ \ | |_) || ||  \| | |  _  / _ \ |  \| |
 ___) |  _  |/ ___ \|  _ < | || |\  | |_| |/ ___ \| |\  |
|____/|_| |_/_/   \_\_| \_\___|_| \_|\____/_/   \_\_| \_|
ART
printf '%s' "$X"
printf '\n'

printf '%s\n' "   ${A}${B}SHARINGAN${X} ${D}- malware triage engine - see through the disguise${X}"
printf '\n'
