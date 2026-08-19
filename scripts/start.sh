#!/bin/bash
# Start praxis credential gateway
# Sourced by launchd via com.praxis.gateway.plist
#
# Consolidates credentials from across the tool stack into env vars,
# then starts praxis. GCP Vertex token is refreshed at startup.

set -euo pipefail

PRAXIS_DIR="$HOME/redhat/praxis"
BINARY="$PRAXIS_DIR/target/release/praxis"
CONFIG="$PRAXIS_DIR/configs/mitzo-gateway.yaml"

if [[ ! -x "$BINARY" ]]; then
  echo "ERROR: praxis binary not found at $BINARY" >&2
  exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
  echo "ERROR: config not found at $CONFIG" >&2
  exit 1
fi

# --- Load credentials from scattered .env files ---

load_env_var() {
  local file="$1" var="$2"
  if [[ -f "$file" ]]; then
    local val
    val=$(grep "^${var}=" "$file" 2>/dev/null | head -1 | cut -d'=' -f2-)
    if [[ -n "$val" ]]; then
      export "$var=$val"
    fi
  fi
}

# OpenAI (zshenv has it, but also check centaur .env as fallback)
[[ -f "$HOME/.zshenv" ]] && source "$HOME/.zshenv"
load_env_var "$HOME/projects/centaur/.env" "OPENAI_API_KEY"

# GitHub PAT
load_env_var "$HOME/projects/centaur/.env" "GITHUB_TOKEN"

# Jira — needs base64 encoding of email:token
load_env_var "$HOME/redhat/mgmt/.env" "JIRA_API_TOKEN"
JIRA_EMAIL="dsaridak@redhat.com"
if [[ -n "${JIRA_API_TOKEN:-}" ]]; then
  export JIRA_API_TOKEN_B64
  JIRA_API_TOKEN_B64=$(printf '%s:%s' "$JIRA_EMAIL" "$JIRA_API_TOKEN" | base64)
fi

# Org Pulse
load_env_var "$HOME/redhat/mgmt/.env" "ORG_PULSE_API_TOKEN"

# ntfy
load_env_var "$HOME/projects/centaur/.env" "NTFY_AUTH_TOKEN"

# --- GCP Vertex AI token (short-lived, refresh at startup) ---
if command -v gcloud &>/dev/null; then
  VERTEX_ACCESS_TOKEN=$(gcloud auth print-access-token 2>/dev/null || true)
  if [[ -n "$VERTEX_ACCESS_TOKEN" ]]; then
    export VERTEX_ACCESS_TOKEN
  else
    echo "WARN: gcloud auth print-access-token failed, Anthropic/Vertex route will 401" >&2
  fi
else
  echo "WARN: gcloud not found, Anthropic/Vertex route will 401" >&2
fi

# --- Validate all credentials are present ---
MISSING=()
check_var() { eval "val=\${$1:-}"; [[ -z "$val" ]] && MISSING+=("$1"); }
check_var OPENAI_API_KEY
check_var GITHUB_TOKEN
check_var JIRA_API_TOKEN_B64
check_var ORG_PULSE_API_TOKEN
check_var NTFY_AUTH_TOKEN
check_var VERTEX_ACCESS_TOKEN

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "WARN: missing credentials: ${MISSING[*]}" >&2
  echo "WARN: routes for missing credentials will return upstream 401/403" >&2
fi

echo "Praxis credential gateway starting on :9090"
echo "  Loaded: $(( 6 - ${#MISSING[@]} ))/6 credentials"
exec "$BINARY" -c "$CONFIG"
