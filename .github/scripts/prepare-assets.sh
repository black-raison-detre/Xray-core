#!/usr/bin/env bash
set -Eeuo pipefail

flavor=${ASSET_FLAVOR:-${1:?Usage: prepare-assets.sh <lite|full> [true|false]}}
include_wintun=${INCLUDE_WINTUN:-${2:-false}}
case "$flavor" in
  lite)
    geoip_url="https://raw.githubusercontent.com/XTLS/Xray-rules-dat/release/geoip/geoip-lite"
    geosite_url="https://raw.githubusercontent.com/XTLS/Xray-rules-dat/release/geosite/geosite"
    ;;
  full)
    geoip_url="https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip"
    geosite_url="https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite"
    ;;
  *)
    echo "Unsupported geodata flavor: $flavor" >&2
    exit 2
    ;;
esac
if [[ "$include_wintun" != "true" && "$include_wintun" != "false" ]]; then
  echo "INCLUDE_WINTUN must be true or false" >&2
  exit 2
fi

wintun_version="0.14.1"
wintun_sha256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
cache_dir=".asset-cache"
resource_dir="resources"
updated=false

mkdir -p "$cache_dir" "$resource_dir"

curl_retry() {
  curl --fail --silent --show-error --location --retry 3 --retry-all-errors --connect-timeout 20 "$@"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print tolower($1) }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print tolower($1) }'
  else
    echo "A SHA256 utility (sha256sum or shasum) is required" >&2
    return 1
  fi
}

ensure_geodata() {
  local name="$1"
  local source_url="$2"
  local cache_file="$cache_dir/$name"
  local expected_sha256 actual_sha256 temporary_file

  expected_sha256="$(curl_retry "$source_url.dat.sha256sum" | awk 'NR == 1 { print tolower($1); exit }')"
  if [[ ! "$expected_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "Invalid SHA256 manifest for $source_url.dat" >&2
    return 1
  fi

  if [[ -s "$cache_file" ]]; then
    actual_sha256="$(sha256_file "$cache_file")"
  else
    actual_sha256=""
  fi

  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    temporary_file="$(mktemp)"
    if ! curl_retry "$source_url.dat" --output "$temporary_file"; then
      rm -f "$temporary_file"
      return 1
    fi
    actual_sha256="$(sha256_file "$temporary_file")"
    if [[ "$actual_sha256" != "$expected_sha256" ]]; then
      echo "SHA256 mismatch for $source_url.dat: expected $expected_sha256, got $actual_sha256" >&2
      rm -f "$temporary_file"
      return 1
    fi
    mv "$temporary_file" "$cache_file"
    updated=true
  fi

  mkdir -p "$resource_dir"
  cp -f "$cache_file" "$resource_dir/$name"
}

ensure_geodata geoip.dat "$geoip_url"
ensure_geodata geosite.dat "$geosite_url"

if [[ "$include_wintun" == "true" ]]; then
  wintun_archive="$cache_dir/wintun-$wintun_version.zip"
  if [[ -s "$wintun_archive" ]]; then
    actual_sha256="$(sha256_file "$wintun_archive")"
  else
    actual_sha256=""
  fi

  if [[ "$actual_sha256" != "$wintun_sha256" ]]; then
    temporary_file="$(mktemp)"
    if ! curl_retry "https://www.wintun.net/builds/wintun-$wintun_version.zip" --output "$temporary_file"; then
      rm -f "$temporary_file"
      exit 1
    fi
    actual_sha256="$(sha256_file "$temporary_file")"
    if [[ "$actual_sha256" != "$wintun_sha256" ]]; then
      echo "SHA256 mismatch for Wintun archive: expected $wintun_sha256, got $actual_sha256" >&2
      rm -f "$temporary_file"
      exit 1
    fi
    mv "$temporary_file" "$wintun_archive"
    updated=true
  fi

  rm -rf "$resource_dir/wintun"
  unzip -oq "$wintun_archive" -d "$resource_dir"
  for architecture in amd64 x86 arm64; do
    file="$resource_dir/wintun/bin/$architecture/wintun.dll"
    if [[ ! -s "$file" ]]; then
      echo "Wintun archive is missing $file" >&2
      exit 1
    fi
  done
  if [[ ! -s "$resource_dir/wintun/LICENSE.txt" ]]; then
    echo "Wintun archive is missing $resource_dir/wintun/LICENSE.txt" >&2
    exit 1
  fi

fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "updated=$updated" >> "$GITHUB_OUTPUT"
else
  echo "updated=$updated"
fi
