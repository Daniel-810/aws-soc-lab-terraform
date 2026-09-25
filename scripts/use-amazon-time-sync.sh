# Points chrony at the Amazon Time Sync Service only.
#
# Embedded into a boot script, not run on its own: relies on the caller's
# `set -euo pipefail`. Inserted as a value, not rendered as a template.
#
# Both images already sync to the link-local service, and the clock was
# right (SR-19). They also list public NTP pools, which the security groups
# block (only 80 and 443 go out). Every attempt was recorded as a rejected
# flow, and those attempts topped the rejected-port chart ahead of real
# internet scanning (ADR-031). The link-local address is reached without
# leaving the host, so it needs no rule and never shows in the flow log.

if [ -d /etc/chrony/sources.d ]; then          # Ubuntu
  chrony_conf=/etc/chrony/chrony.conf
  chrony_sources=/etc/chrony/sources.d
  chrony_service=chrony
else                                           # Amazon Linux 2023
  chrony_conf=/etc/chrony.conf
  chrony_sources=/etc/chrony.d
  chrony_service=chronyd
fi

# Every configured source is commented out, then the one wanted is added.
# Editing only the pool lines would depend on how each image happens to
# name its sources.
for f in "$chrony_conf" "$chrony_sources"/*.sources; do
  # if rather than `[ -f ] && sed`: as the last command of the loop, a false
  # test would end the loop with status 1, which set -e may treat as fatal.
  if [ -f "$f" ]; then
    sed -i -E 's/^(pool|server)[[:space:]]/# &/' "$f"
  fi
done
# Sources can also arrive at boot under /run: Amazon Linux links its public
# pool there, and Ubuntu writes servers learned from DHCP. Those directories
# are not read either.
sed -i -E 's|^sourcedir[[:space:]]+/run/|# &|' "$chrony_conf"
echo "server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4" \
  > "$chrony_sources/amazon-time-sync.sources"
systemctl restart "$chrony_service"

# A clock that silently stops syncing reorders every log line (T-08), so
# the boot fails rather than carry on without a source.
chrony_deadline=$((SECONDS + 120))
until chronyc -n sources | grep -q '^\^\* 169\.254\.169\.123'; do
  if (( SECONDS >= chrony_deadline )); then
    echo "chrony did not select the Amazon Time Sync Service" >&2
    chronyc -n sources >&2 || true
    exit 1
  fi
  sleep 3
done
