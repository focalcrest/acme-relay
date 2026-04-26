#!/usr/bin/env sh

# acme.sh DNS plugin for acme-relay
# Uses the acme-relay DNS API to manage TXT records via AliDNS.
#
# Environment variables:
#   ACMERELAY_URL     - Base URL of the acme-relay server (e.g., http://relay:8080)
#   ACMERELAY_API_KEY - API key for authentication

####################  Public functions ####################

# Usage: dns_acmerelay_add _acme-challenge.example.com "XyZ..."
dns_acmerelay_add() {
  _fqdn="$1"
  _txtvalue="$2"

  ACMERELAY_URL="${ACMERELAY_URL:-$(_readaccountconf_mutable ACMERELAY_URL)}"
  ACMERELAY_API_KEY="${ACMERELAY_API_KEY:-$(_readaccountconf_mutable ACMERELAY_API_KEY)}"

  if [ -z "$ACMERELAY_URL" ]; then
    _err "ACMERELAY_URL is not set"
    return 1
  fi

  if [ -z "$ACMERELAY_API_KEY" ]; then
    _err "ACMERELAY_API_KEY is not set"
    return 1
  fi

  _saveaccountconf_mutable ACMERELAY_URL "$ACMERELAY_URL"
  _saveaccountconf_mutable ACMERELAY_API_KEY "$ACMERELAY_API_KEY"

  _info "Adding TXT record via acme-relay: $_fqdn"

  response="$(_post "{\"fqdn\":\"$_fqdn\",\"value\":\"$_txtvalue\"}" \
    "$ACMERELAY_URL/api/v1/dns/txt/add" \
    "" POST "application/json" \
    "Authorization: Bearer $ACMERELAY_API_KEY")"

  if [ "$?" != "0" ]; then
    _err "Failed to add TXT record via acme-relay"
    _err "$response"
    return 1
  fi

  _info "TXT record added successfully"
  return 0
}

# Usage: dns_acmerelay_rm _acme-challenge.example.com "XyZ..."
dns_acmerelay_rm() {
  _fqdn="$1"
  _txtvalue="$2"

  ACMERELAY_URL="${ACMERELAY_URL:-$(_readaccountconf_mutable ACMERELAY_URL)}"
  ACMERELAY_API_KEY="${ACMERELAY_API_KEY:-$(_readaccountconf_mutable ACMERELAY_API_KEY)}"

  if [ -z "$ACMERELAY_URL" ]; then
    _err "ACMERELAY_URL is not set"
    return 1
  fi

  if [ -z "$ACMERELAY_API_KEY" ]; then
    _err "ACMERELAY_API_KEY is not set"
    return 1
  fi

  _info "Removing TXT record via acme-relay: $_fqdn"

  response="$(_post "{\"fqdn\":\"$_fqdn\",\"value\":\"$_txtvalue\"}" \
    "$ACMERELAY_URL/api/v1/dns/txt/remove" \
    "" POST "application/json" \
    "Authorization: Bearer $ACMERELAY_API_KEY")"

  if [ "$?" != "0" ]; then
    _err "Failed to remove TXT record via acme-relay"
    _err "$response"
    return 1
  fi

  _info "TXT record removed successfully"
  return 0
}
