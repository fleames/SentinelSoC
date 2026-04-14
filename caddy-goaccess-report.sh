#!/bin/bash
# Caddy JSON access log -> GoAccess HTML report
# Deploy: chmod +x /opt/scripts/caddy-goaccess-report.sh && run from cron with flock

set -eu
# Note: no pipefail -- grep exits 1 when there are zero matches; last stage still writes output.

PATH=/usr/bin:/usr/local/bin:/bin

LOG_FILE="${LOG_FILE:-/var/log/caddy/all-access.log}"
TMP_LOG="${TMP_LOG:-/tmp/caddy-tail.log}"
TMP_INPUT="${TMP_INPUT:-/tmp/goaccess-input.log}"
TMP_INPUT_NEW="${TMP_INPUT_NEW:-/tmp/goaccess-input.new.log}"
OUT_FILE="${OUT_FILE:-/var/www/html/report.html}"
DEBUG_LOG="${DEBUG_LOG:-/tmp/goaccess-debug.log}"
LOCK_FILE="${LOCK_FILE:-/tmp/caddy-goaccess-report.lock}"
TAIL_LINES="${TAIL_LINES:-5000}"

GEOIP_COUNTRY="${GEOIP_COUNTRY:-/usr/share/GeoIP/GeoLite2-Country.mmdb}"
GEOIP_ASN="${GEOIP_ASN:-/usr/share/GeoIP/GeoLite2-ASN.mmdb}"

# Comma-separated list; matched case-insensitively against Referer
INTERNAL_REFERER_MARKERS="${INTERNAL_REFERER_MARKERS:-fluxconvert.app,neuroprompt.dev,nullpaste.org}"

echo "RUN $(date -Is)" >>"$DEBUG_LOG"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "SKIP already running $(date -Is)" >>"$DEBUG_LOG"
  exit 0
fi

# Optional: cap debug log size (~last 2000 lines)
if [[ -f "$DEBUG_LOG" ]] && [[ $(wc -l <"$DEBUG_LOG" 2>/dev/null || echo 0) -gt 5000 ]]; then
  tail -n 2000 "$DEBUG_LOG" >"${DEBUG_LOG}.tmp" && mv "${DEBUG_LOG}.tmp" "$DEBUG_LOG"
fi

sleep 1
/usr/bin/tail -n "$TAIL_LINES" "$LOG_FILE" >"$TMP_LOG"

# Pass internal referer markers into jq as JSON array
IFS=',' read -r -a _markers <<<"$INTERNAL_REFERER_MARKERS"
MARKERS_JSON=$(printf '%s\n' "${_markers[@]}" | jq -R . | jq -s .)

/usr/bin/jq -rc --argjson internal "$MARKERS_JSON" '
select(.request != null) |

def s(x):
  if x == null then "-"
  elif (x | type) == "string" then x
  elif (x | type) == "number" then (x | tostring)
  else (x | tostring)
  end;

def hdr($n):
  if .request.headers == null then empty
  elif .request.headers[$n] != null then .request.headers[$n][0]
  else empty
  end;

def hdr_ci($want):
  if .request.headers == null then empty
  else
    first(.request.headers | to_entries[]
      | select(.key | ascii_downcase == ($want | ascii_downcase))
      | .value[0])
  end;

def first_ip_from_forward(s):
  if s == null or s == "" or s == "-" then empty
  else (s | split(",")[0] | gsub("^\\s+";"") | gsub("\\s+$";""))
  end;

# Client IP: Cloudflare header first, then X-Forwarded-For first hop, then remote_ip
( first_ip_from_forward(hdr("Cf-Connecting-Ip"))
  // first_ip_from_forward(hdr("cf-connecting-ip"))
  // first_ip_from_forward(hdr_ci("Cf-Connecting-Ip"))
  // first_ip_from_forward(hdr("X-Forwarded-For"))
  // first_ip_from_forward(hdr("x-forwarded-for"))
  // s(.request.remote_ip)
) as $ip |

s(.request.uri) as $uri |
s(.request.method) as $method |
(.status // 0) as $status |
(.size // 0) as $size |

( hdr("User-Agent") // hdr("user-agent") // hdr_ci("User-Agent") ) as $ua_raw |
( hdr("Referer") // hdr("referer") // hdr_ci("Referer") ) as $ref_raw |

# Host: Caddy puts canonical host on .request.host; headers are fallback
(
  if (.request.host | type) == "string" and (.request.host | length) > 0 then .request.host
  else (hdr("Host") // hdr("host") // hdr_ci("Host") // "-")
  end
) as $host_raw |

s($ua_raw) as $ua |
s($ref_raw) as $ref |
s($host_raw) as $host |

($ua | ascii_downcase) as $ua_lc |
($ref | ascii_downcase) as $ref_lc |

( any(internal[]; $ref_lc | contains(.)) ) as $internal |

( if $internal then "-" else $ref end ) as $ref_clean |

( $ua_lc | (contains("bot") or contains("curl") or contains("python") or contains("wget") or contains("scanner")) ) as $bot |
( $uri | (contains(".git") or contains(".env") or contains("admin") or contains("config") or contains("settings")) ) as $attack |

( if $attack then "/ATTACK" + $uri
  elif $bot then "/BOT" + $uri
  else $uri
  end
) as $final_uri |

# GoAccess line: IP [date] method uri status size "ref" "ua" vhost
"\($ip) [\(.ts | strftime("%d/%b/%Y:%H:%M:%S %z"))] \($method) \($final_uri) \($status) \($size) \"\($ref_clean)\" \"\($ua)\" \($host)"
' "$TMP_LOG" 2>>"$DEBUG_LOG" |
grep -E '^[0-9a-fA-F:.]+ \[[0-9]{2}/' |
sed '/^$/d' |
awk 'NR==1 && $0 !~ /^[0-9a-fA-F:.]+ \[/ {next} {print}' \
  >"$TMP_INPUT_NEW"

LINES=$(wc -l <"$TMP_INPUT_NEW" | tr -d ' ')
echo "LINES: $LINES" >>"$DEBUG_LOG"

if [[ "${LINES:-0}" -eq 0 ]]; then
  echo "ERROR: no valid lines, keeping old data $(date -Is)" >>"$DEBUG_LOG"
  exit 0
fi

mv -f "$TMP_INPUT_NEW" "$TMP_INPUT"

/usr/bin/goaccess "$TMP_INPUT" \
  --log-format='%h [%d:%t %^] %m %U %s %b "%R" "%u" %v' \
  --date-format=%d/%b/%Y \
  --time-format=%H:%M:%S \
  --geoip-database="$GEOIP_COUNTRY" \
  --geoip-database="$GEOIP_ASN" \
  --no-query-string \
  --enable-panel=VISITORS \
  --enable-panel=HOSTS \
  --enable-panel=VIRTUAL_HOSTS \
  --enable-panel=ASN \
  --enable-panel=GEO_LOCATION \
  --enable-panel=REFERRERS \
  -o "$OUT_FILE" >>"$DEBUG_LOG" 2>&1

echo "DONE $(date -Is)" >>"$DEBUG_LOG"
