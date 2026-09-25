# Installs the CloudWatch agent on Ubuntu from AWS's own download bucket.
#
# Embedded into a boot script, not run on its own: expects REGION and
# VERSIONS_FILE to be set, and relies on the caller's `set -euo pipefail`.
#
# The Ubuntu archive has no package for the agent, so the .deb comes from
# AWS directly and is only installed if its signature was made by the key
# whose fingerprint is written below (ADR-028). The fingerprint is the one
# AWS publishes in its documentation. It is checked instead of trusting the
# key file, because the key and the package come from the same place: if
# that place were tampered with, both could be replaced together.

CWA_FINGERPRINT="937616F3450B7D806CBD9725D58167303B789C72"
CWA_BASE="https://amazoncloudwatch-agent-$REGION.s3.$REGION.amazonaws.com/ubuntu/amd64/latest"

cwa_dir=$(mktemp -d)
export GNUPGHOME="$cwa_dir/gnupg"
mkdir -m 700 "$GNUPGHOME"

curl -fsS --retry 5 -o "$cwa_dir/key.gpg" \
  https://amazoncloudwatch-agent.s3.amazonaws.com/assets/amazon-cloudwatch-agent.gpg
curl -fsS --retry 5 -o "$cwa_dir/agent.deb"     "$CWA_BASE/amazon-cloudwatch-agent.deb"
curl -fsS --retry 5 -o "$cwa_dir/agent.deb.sig" "$CWA_BASE/amazon-cloudwatch-agent.deb.sig"

gpg --batch --quiet --import "$cwa_dir/key.gpg"

# VALIDSIG is printed only for a good signature, and it names the key that
# made it. Requiring our fingerprint there covers both conditions at once:
# the file is intact, and it was signed by the expected key.
if ! gpg --batch --status-fd 1 --verify "$cwa_dir/agent.deb.sig" "$cwa_dir/agent.deb" 2>/dev/null \
    | grep -q "^\[GNUPG:\] VALIDSIG .*$CWA_FINGERPRINT"; then
  echo "CloudWatch agent signature not made by the expected key" >&2
  exit 1
fi

dpkg -i "$cwa_dir/agent.deb"

# Recorded rather than pinned: the download path only serves the latest
# build (ADR-021). This file is inserted into the boot scripts as a value,
# not rendered as a template, so no $$ escaping is needed here.
dpkg-query -W -f='${Package} ${Version}\n' amazon-cloudwatch-agent >> "$VERSIONS_FILE"

unset GNUPGHOME
rm -rf "$cwa_dir"
