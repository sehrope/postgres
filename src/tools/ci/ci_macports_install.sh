#!/bin/bash
#
# Install the requested MacPorts packages, caching the installation as a
# compressed .dmg so CI runs stay fast. The cached image is only rewritten
# when packages are actually installed or removed. Any package not named on
# the command line is treated as superfluous and uninstalled.
#
# This expects to run on a macOS GitHub Actions runner. It is written to work
# with the system bash (3.2.57) shipped on macOS, so it avoids bash 4+
# features (associative arrays, ${var,,}, mapfile, etc.).
#
# Usage: install-macports.sh PACKAGE [PACKAGE ...]
#
# Environment:
#   MACPORTS_CACHE  directory in which the cached image is stored (required)
set -euo pipefail

if [[ "$CI" != "true" ]]; then
    echo "expect to be called within CI" 1>2
    exit 1
fi

# If GitHub Actions debug mode is enabled then pass it through here too.
[[ -z "${RUNNER_DEBUG:-}" ]] || set -x

readonly CACHE_DMG="macports.hfs.dmg"
readonly PREFIX="/opt/local"

log() {
    printf '%s\n' "$*" >&2
}

err() {
    log "error: $*"
    exit 1
}

# Map a macOS major version to the codename MacPorts uses in its release asset
# filenames (e.g. MacPorts-2.11.5-14-Sonoma.pkg). Prints the codename, or
# returns non-zero for an unrecognised version.
get_macos_codename() {
    local major="$1"
    case "$major" in
        26) printf 'Tahoe'    ;;
        15) printf 'Sequoia'  ;;
        14) printf 'Sonoma'   ;;
        13) printf 'Ventura'  ;;
        12) printf 'Monterey' ;;
        11) printf 'BigSur'   ;;
        *)  return 1          ;;
    esac
}

# Print the download URL of the MacPorts .pkg matching this host. Fatal if the
# macOS version is unsupported or the latest MacPorts version can't be read.
get_macports_url() {
    local major codename release_json version

    major="$( sw_vers -productVersion | sed 's/\..*//' )"
    log "macos major version = ${major}"
    [[ -n "${major}" ]] || err "could not determine macOS major version"

    # get_macos_codename returns non-zero for unsupported versions; check it
    # explicitly, since an assignment from a failed substitution does not
    # reliably trip set -e.
    if ! codename="$( get_macos_codename "${major}" )"; then
        err "unsupported macOS major version: ${major}"
    fi
    log "macos codename = ${codename}"

    release_json="$( curl -fsSL https://api.github.com/repos/macports/macports-base/releases/latest )"
    version="$( jq -r '.tag_name | ltrimstr("v")' <<<"${release_json}" )"
    [[ -n "${version}" && "${version}" != "null" ]] || err "could not determine MacPorts version"
    log "macports version = ${version}"

    printf '%s' "https://github.com/macports/macports-base/releases/download/v${version}/MacPorts-${version}-${major}-${codename}.pkg"
}

# Bring up a working MacPorts install: mount the cached image if one exists,
# otherwise install the matching .pkg fresh. Assigns "new" or "cached" to the
# variable named by $1.
#
# Result is returned via printf -v rather than stdout so this function can be
# called directly: a fatal error in the nested get_macports_url then aborts the
# script under set -e, which capturing in $(...) would swallow.
install_macports() {
    local result_var="$1"
    local cache_zstd="${MACPORTS_CACHE}/${CACHE_DMG}.zstd"

    sudo mkdir -p "${PREFIX}"
    mkdir -p "${MACPORTS_CACHE}/"

    if [[ -e "${cache_zstd}" ]]; then
        log "warm cache: mounting existing image"
        zstd -T0 -d "${cache_zstd}" -o "${CACHE_DMG}"
        sudo hdiutil attach -kernel "${CACHE_DMG}" -owners on \
            -shadow "${CACHE_DMG}.shadow" -mountpoint "${PREFIX}"
        printf -v "${result_var}" '%s' "cached"
        return
    fi

    log "cold cache: performing fresh MacPorts install"
    local macports_url
    macports_url="$( get_macports_url )"
    log "macports url = ${macports_url}"
    curl -fsSL -o macports.pkg "${macports_url}"
    sudo installer -pkg macports.pkg -target /
    # Throwaway environment: run everything as root rather than creating a user.
    echo macportsuser root | sudo tee -a "${PREFIX}/etc/macports/macports.conf" >/dev/null
    printf -v "${result_var}" '%s' "new"
}

# Reconcile installed packages with the requested set. Assigns "changed" if it
# installed anything, "unchanged" otherwise, to the variable named by $1. The
# requested packages follow as $2...
sync_requested_packages() {
    local result_var="$1"; shift
    local changed=0
    local package

    # Mark everything currently installed as unrequested, so that anything we
    # do not re-request below becomes detectable as a leaf to remove.
    if [[ -n "$( port -q installed installed )" ]]; then
        sudo port unsetrequested installed
    fi

    # Re-request each wanted package. port setrequested only reports a failure
    # for the first missing package, so check them one at a time.
    log "checking if all required packages are installed"
    for package in "$@"; do
        if ! sudo port setrequested "${package}" >/dev/null 2>&1; then
            changed=1
        fi
    done

    if [[ "${changed}" -eq 0 ]]; then
        printf -v "${result_var}" '%s' "unchanged"
        return
    fi

    log "not all required packages installed; installing now"
    # The ports tree was stripped from the cached image to keep it small.
    sudo port selfupdate
    sudo port upgrade outdated
    sudo port install -N "$@"
    sudo port setrequested "$@"
    printf -v "${result_var}" '%s' "changed"
}

# Remove any packages that are no longer requested. Assigns "changed" if it
# removed anything, "unchanged" otherwise, to the variable named by $1.
remove_superfluous_packages() {
    local result_var="$1"

    if [[ -z "$( port -q installed rleaves )" ]]; then
        printf -v "${result_var}" '%s' "unchanged"
        return
    fi

    log "superfluous packages installed; removing"
    sudo port uninstall --follow-dependencies rleaves
    # Drop the prior cache contents so the rewritten image does not grow.
    rm -f "${MACPORTS_CACHE}"/*
    printf -v "${result_var}" '%s' "changed"
}

# Shrink the live installation before it gets imaged.
shrink_installation() {
    sudo "${PREFIX}/bin/port" clean --all installed
    sudo rm -rf "${PREFIX}/var/macports/software/"* \
                "${PREFIX}/var/macports/sources/"*
}

# Write a brand-new compressed image from the live installation.
create_cached_image() {
    # Generous size so more software can be added to the image later.
    sudo hdiutil create -fs HFS+ -format UDRO -size 10g -layout NONE \
        -srcfolder "${PREFIX}" "${CACHE_DMG}"
    zstd -T -10 -z "${CACHE_DMG}" -o "${MACPORTS_CACHE}/${CACHE_DMG}.zstd"
}

# Fold the shadow file's changes back into the cached image and remount.
update_cached_image() {
    sudo hdiutil detach "${PREFIX}"
    hdiutil convert -format UDRO "${CACHE_DMG}" \
        -shadow "${CACHE_DMG}.shadow" -o updated.hfs.dmg
    rm "${CACHE_DMG}.shadow"
    mv updated.hfs.dmg "${CACHE_DMG}"
    zstd --force -T -10 -z "${CACHE_DMG}" -o "${MACPORTS_CACHE}/${CACHE_DMG}.zstd"
    sudo hdiutil attach -kernel "${CACHE_DMG}" -owners on \
        -shadow "${CACHE_DMG}.shadow" -mountpoint "${PREFIX}"
}

main() {
    [[ "$#" -ge 1 ]] || err "usage: $0 PACKAGE [PACKAGE ...]"
    [[ -n "${MACPORTS_CACHE:-}" ]] || err "MACPORTS_CACHE must be set"

    # After this we have a working MacPorts install with an unknown package set.
    local install_state
    install_macports install_state

    # Put the freshly available tools on PATH for the rest of the run.
    PATH="${PREFIX}/sbin:${PREFIX}/bin:${PATH}"
    export PATH

    local sync_state remove_state
    sync_requested_packages sync_state "$@"
    remove_superfluous_packages remove_state

    # Rewrite the cached image only when we actually changed the installation.
    if [[ "${install_state}" = "new" ]]; then
        shrink_installation
        create_cached_image
    elif [[ "${sync_state}" = "changed" || "${remove_state}" = "changed" ]]; then
        shrink_installation
        update_cached_image
    else
        log "installation unchanged; leaving cache as-is"
    fi

    log "done"
}

main "$@"
