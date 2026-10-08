#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 CLIENT_TOKEN_FILE PUBLICATION_JOURNAL [--initialize-publication-journal]" >&2
  exit 2
fi

publication_journal="$2"
if [ "$#" -eq 3 ] && [ "$3" != "--initialize-publication-journal" ]; then
  echo "unknown initialization option" >&2
  exit 2
fi

asterctl() {
  mise exec -- cargo run --quiet --locked -p asterctl -- "$@"
}

# Initialization is explicit and refuses to overwrite an existing journal.
if [ "$#" -eq 3 ]; then
  asterctl publication-init --journal "$publication_journal" --client-id connect-quickstart/v1
fi
asterctl --token-file "$1" --json publication-recover \
  --journal "$publication_journal" --client-id connect-quickstart/v1

ASTER_CLIENT_TOKEN="$(tr -d '\r\n' < "$1")"
ASTER_AGENT_URL="http://127.0.0.1:8181"

rpc() {
  method="$1"
  data="$2"
  mise exec -- buf curl --schema . --reflect=false \
    -H "Authorization: Bearer $ASTER_CLIENT_TOKEN" \
    -d "$data" \
    "$ASTER_AGENT_URL/aster.application.v1alpha1.AsterApplicationService/$method"
}

rpc GetStatus '{}'
subscription="$(rpc CreateEventSubscription \
  '{"operationKey":"Y29ubmVjdC1xdWlja3N0YXJ0LXN1YnNjcmlwdGlvbg==","topic":"chat.events","scope":"mission/team/alpha"}')"
subscription_id="$(printf '%s' "$subscription" | jq -r .subscriptionId)"

# The CLI persists the full intent and numbered result before returning.
# Preserve publication results until application progress is durably applied;
# acknowledge them explicitly with asterctl publication-ack afterwards.
asterctl --token-file "$1" --json publish \
  --journal "$publication_journal" --client-id connect-quickstart/v1 \
  --topic chat.events --scope mission/team/alpha --logical-key asset-7 ready
page="$(rpc PollEvents \
  "{\"subscriptionId\":\"$subscription_id\",\"deliveryLimit\":8,\"scanLimit\":32}")"
printf '%s\n' "$page"
event_id="$(printf '%s' "$page" | jq -r '.deliveries[0].event.id // empty')"
if [ -n "$event_id" ]; then
  rpc AcknowledgeEvent \
    "{\"subscriptionId\":\"$subscription_id\",\"eventId\":\"$event_id\"}"
fi
