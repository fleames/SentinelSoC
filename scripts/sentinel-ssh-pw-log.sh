#!/bin/bash
# sentinel-ssh-pw-log.sh -- PAM exec script to capture SSH password attempts.
#
# Installation:
#   1. Copy this file to /usr/local/bin/sentinel-ssh-pw-log.sh
#   2. chmod 700 /usr/local/bin/sentinel-ssh-pw-log.sh
#   3. chown root:root /usr/local/bin/sentinel-ssh-pw-log.sh
#   4. touch /var/log/sentinel-ssh-passwords.log
#      chmod 600 /var/log/sentinel-ssh-passwords.log
#      chown root:root /var/log/sentinel-ssh-passwords.log
#   5. Add to /etc/pam.d/sshd (before @include common-auth):
#        auth optional pam_exec.so expose_authtok quiet /usr/local/bin/sentinel-ssh-pw-log.sh
#   6. Set SSH_PAM_LOG=/var/log/sentinel-ssh-passwords.log in the sentinel_ssh_ingest environment
#   7. systemctl reload ssh  (or sshd on some distros)
#
# Log format: epoch|remote_ip|username|password (one attempt per line)
# Log file must be readable by the sentinel_ssh_ingest process user.
#
# Security note: this file logs cleartext passwords attempted against your server.
# Restrict permissions accordingly. Rotate and purge regularly.
# Only attempted (failed) passwords are expected here, but PAM cannot distinguish
# pass/fail at the time it runs -- if a legitimate user logs in successfully, that
# password will also appear. Limit access to root and the sentinel service account.

[ "$PAM_TYPE" = "auth" ] || exit 0

# Read password from stdin (pam_exec expose_authtok pipes it here)
read -r password

# Skip empty or suspiciously short inputs (SSH scanners often send garbage)
[ -z "$password" ] && exit 0

LOG=/var/log/sentinel-ssh-passwords.log
TS=$(date -u +%s)

printf '%s|%s|%s|%s\n' \
    "$TS" \
    "${PAM_RHOST:-}" \
    "${PAM_USER:-}" \
    "${password}" \
    >> "$LOG" 2>/dev/null

exit 0
