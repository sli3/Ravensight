#!/bin/sh
set -eu

# All Ravensight settings live in the mounted /app/config.toml. This script
# only handles Docker concerns: the container user, folder ownership, seeding
# default files and the initial reference-data syncs. The container paths are
# fixed: /app/data, /app/reports and /app/config.toml.
data_dir=/app/data
reports_dir=/app/reports

# --- Required variables: fail fast with a clear message rather than let
# an unset variable abort the script with an unbound-variable error ---
required_vars="RAVENSIGHT_PUID RAVENSIGHT_PGID"
missing=""
for var in $required_vars; do
    eval "value=\${$var:-}"
    if [ -z "$value" ]; then
        missing="$missing $var"
    fi
done
if [ -n "$missing" ]; then
    echo "ERROR: missing required environment variable(s):$missing" >&2
    echo "Set these in your .env file before starting the container." >&2
    exit 1
fi

case "$RAVENSIGHT_PUID$RAVENSIGHT_PGID" in
    ''|*[!0-9]*)
        echo 'ERROR: RAVENSIGHT_PUID and RAVENSIGHT_PGID must be numbers. On the host run `id -u` and `id -g` and put the results in .env. Rootless Docker/Podman: use 0 for both.' >&2
        exit 1
        ;;
esac

if [ "$RAVENSIGHT_PUID" = "0" ] && [ "$RAVENSIGHT_PGID" != "0" ]; then
    echo 'ERROR: RAVENSIGHT_PUID=0 means rootless Docker/Podman mode — set RAVENSIGHT_PGID=0 as well.' >&2
    exit 1
fi

if [ "$(id -u)" != "0" ]; then
    echo "ERROR: this container was started with --user or Compose user:, which this image does not support." >&2
    echo "Remove it and set RAVENSIGHT_PUID and RAVENSIGHT_PGID in your .env file instead." >&2
    exit 1
fi

run_as() {
    if [ "$RAVENSIGHT_PUID" = "0" ]; then
        "$@"
    else
        setpriv --reuid="$RAVENSIGHT_PUID" --regid="$RAVENSIGHT_PGID" --clear-groups "$@"
    fi
}

# --- The mounted config.toml must exist and be readable by the app user.
# Skipped for init-attestation, init-essentials-attestation and sync, which run
# without a config.toml.
# [ ! -f ] also catches Docker creating a directory for a missing host file ---
if [ "${1:-}" != "init-attestation" ] && [ "${1:-}" != "init-essentials-attestation" ] && [ "${1:-}" != "sync" ]; then
    if [ ! -f /app/config.toml ]; then
        echo "ERROR: /app/config.toml is missing or is not a file. Copy config.example.toml to config.toml, fill in your settings, and mount it (see RAVENSIGHT_HOST_CONFIG_PATH in .env.example)." >&2
        exit 1
    fi
    if ! run_as test -r /app/config.toml; then
        echo "ERROR: /app/config.toml exists but is not readable by uid $RAVENSIGHT_PUID." >&2
        echo "Fix it on the host with chmod or chown so that user can read the file." >&2
        exit 1
    fi
fi

mkdir -p "$data_dir" "$reports_dir"

# --- Repair ownership of mismatched entries inside the mounted volumes ---
# Runs on every start but only touches entries not already owned by
# PUID:PGID (e.g. files written by an older root-run container).
for dir in "$data_dir" "$reports_dir"; do
    repaired=$(find "$dir" \( ! -user "$RAVENSIGHT_PUID" -o ! -group "$RAVENSIGHT_PGID" \) -exec chown -h "$RAVENSIGHT_PUID:$RAVENSIGHT_PGID" {} + -print | wc -l)
    still_bad=$(find "$dir" \( ! -user "$RAVENSIGHT_PUID" -o ! -group "$RAVENSIGHT_PGID" \) -print -quit 2>/dev/null || echo "$dir")
    if [ -n "$still_bad" ]; then
        echo "WARNING: some entries in $dir could not be re-owned to $RAVENSIGHT_PUID:$RAVENSIGHT_PGID (read-only mount or NFS root-squash?). Ravensight may fail to write there. Fix on the host: sudo chown -R $RAVENSIGHT_PUID:$RAVENSIGHT_PGID on the folder mounted at $dir." >&2
    elif [ "$repaired" -gt 0 ]; then
        echo "Repaired ownership of $repaired entries in $dir"
    fi
done

# --- On-demand attestation template: `docker run <image> init-attestation`
# copies the example into the data folder without overwriting an existing
# file. Runs before any sync, so it needs no network ---
if [ "${1:-}" = "init-attestation" ]; then
    if [ -f "$data_dir/e8_attestation.json" ]; then
        echo "$data_dir/e8_attestation.json already exists, left unchanged."
        exit 0
    fi
    if [ ! -f /app/defaults/e8_attestation.example.json ]; then
        echo "ERROR: missing default file /app/defaults/e8_attestation.example.json" >&2
        exit 1
    fi
    run_as cp /app/defaults/e8_attestation.example.json "$data_dir/e8_attestation.json"
    echo "Created $data_dir/e8_attestation.json from the example."
    echo "Edit it with your real attestations and remove the EXAMPLE: prefixes; it is picked up on the next start."
    exit 0
fi

# --- On-demand Essentials attestation template: `docker run <image>
# init-essentials-attestation` copies the example into the data folder
# without overwriting an existing file. Needs no network ---
if [ "${1:-}" = "init-essentials-attestation" ]; then
    if [ -f "$data_dir/essentials_attestation.json" ]; then
        echo "$data_dir/essentials_attestation.json already exists, left unchanged."
        exit 0
    fi
    if [ ! -f /app/defaults/essentials_attestation.example.json ]; then
        echo "ERROR: missing default file /app/defaults/essentials_attestation.example.json" >&2
        exit 1
    fi
    run_as cp /app/defaults/essentials_attestation.example.json "$data_dir/essentials_attestation.json"
    echo "Created $data_dir/essentials_attestation.json from the example."
    echo "Edit it with your real declarations and remove the EXAMPLE: prefixes; it is picked up on the next start."
    exit 0
fi

# --- Seed hand-edited default files only if the user hasn't provided their
# own (never overwrite an existing file in the mounted data volume) ---
if [ ! -f "$data_dir/e8_keyword_overrides.json" ]; then
    if [ ! -f /app/defaults/e8_keyword_overrides.json ]; then
        echo "WARNING: missing default file /app/defaults/e8_keyword_overrides.json — skipping seed" >&2
    else
        run_as cp /app/defaults/e8_keyword_overrides.json "$data_dir/e8_keyword_overrides.json"
    fi
fi

if [ ! -f "$data_dir/platform_hints.json" ]; then
    if [ ! -f /app/defaults/platform_hints.json ]; then
        echo "WARNING: missing default file /app/defaults/platform_hints.json — skipping seed" >&2
    else
        run_as cp /app/defaults/platform_hints.json "$data_dir/platform_hints.json"
    fi
fi

# --- Sync reference data only if missing (not on every start) ---
if [ ! -f "$data_dir/mitre_attack.json" ]; then
    echo "MITRE ATT&CK data not found — running initial sync..."
    run_as python3 scripts/mitre_sync.py --output "$data_dir/mitre_attack.json"
fi

if [ ! -f "$data_dir/asd_framework.json" ]; then
    echo "ASD framework data not found — running initial sync..."
    run_as python3 scripts/asd_sync.py --output "$data_dir/asd_framework.json"
fi

# --- On-demand forced re-sync: `docker run <image> sync` refreshes both
# reference datasets even if they already exist (e.g. a new MITRE ATT&CK
# or ASD ISM release), bypassing the missing-file check above ---
if [ "${1:-}" = "sync" ]; then
    echo "Forcing MITRE ATT&CK + ASD framework re-sync..."
    run_as python3 scripts/mitre_sync.py --output "$data_dir/mitre_attack.json"
    run_as python3 scripts/asd_sync.py --output "$data_dir/asd_framework.json"
    echo "Sync complete."
    exit 0
fi

if [ "$RAVENSIGHT_PUID" = "0" ]; then
    exec "$@"
else
    exec setpriv --reuid="$RAVENSIGHT_PUID" --regid="$RAVENSIGHT_PGID" --clear-groups "$@"
fi