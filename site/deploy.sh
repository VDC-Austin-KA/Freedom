#!/usr/bin/env bash
# Deploys the download page + wifi_scanner.py to https://radar.ackerworks.com as a Cloudflare Worker.
# Needs CLOUDFLARE_API_TOKEN (Edit Cloudflare Workers template + Zone DNS Edit on ackerworks.com).
set -euo pipefail
cd "$(dirname "$0")/.."
ZONE=ackerworks.com HOST=radar.ackerworks.com NAME=radar
API=https://api.cloudflare.com/client/v4
cf() { curl -sS --fail-with-body -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}" "$@"; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin)['result'][0]['$1'])"; }

zone=$(cf "$API/zones?name=$ZONE")
ZONE_ID=$(field id <<<"$zone")
ACCOUNT_ID=$(python3 -c "import json,sys; print(json.load(sys.stdin)['result'][0]['account']['id'])" <<<"$zone")

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
python3 - "$tmp/worker.js" <<'EOF'
import json, sys
files = {
    '/': [open('site/index.html').read(), 'text/html; charset=utf-8'],
    '/wifi_scanner.py': [open('wifi_scanner.py').read(), 'text/x-python; charset=utf-8'],
}
open(sys.argv[1], 'w').write('const FILES = %s;\n' % json.dumps(files) + '''
export default {
  fetch(req) {
    const f = FILES[new URL(req.url).pathname];
    if (!f) return new Response('Not found', {status: 404});
    return new Response(f[0], {headers: {
      'content-type': f[1], 'x-content-type-options': 'nosniff', 'cache-control': 'public, max-age=300',
    }});
  },
};
''')
EOF

cf -X PUT "$API/accounts/$ACCOUNT_ID/workers/scripts/$NAME" \
  -F 'metadata={"main_module":"worker.js","compatibility_date":"2025-01-01"};type=application/json' \
  -F "worker.js=@$tmp/worker.js;type=application/javascript+module" >/dev/null
echo "Uploaded worker '$NAME'"

cf -X PUT "$API/accounts/$ACCOUNT_ID/workers/domains" -H 'Content-Type: application/json' \
  -d "{\"hostname\":\"$HOST\",\"zone_id\":\"$ZONE_ID\",\"service\":\"$NAME\",\"environment\":\"production\"}" >/dev/null
echo "Attached https://$HOST"
