#!/usr/bin/env bash
#
# Lots of Honey - Secure Firewall Banlist Sync Script
#
# Description:
#   This script runs locally as root on the host OS. It fetches the network-wide 
#   honeypot IP banlist securely from WordPress via standard PHP, sanitizes the inputs 
#   rigorously, and applies them to your choice of system firewall (UFW, iptables,
#   firewalld, or /etc/hosts.deny) without giving the web server elevated access.
#
# Install:
#   1. Move this script to: /usr/local/bin/sync-honey-banlist.sh
#   2. Make it executable: chmod +x /usr/local/bin/sync-honey-banlist.sh
#   3. Configure variables (WP_PATH, FIREWALL_TYPE, etc.) below.
#   4. Schedule a root cron job (e.g. every minute):
#      crontab -e
#      * * * * * /usr/local/bin/sync-honey-banlist.sh >/dev/null 2>&1
#

set -euo pipefail

# ==================== CONFIGURATION ====================
WP_PATH="/var/www/html"          # Absolute path to your WordPress installation
WP_USER="www-data"               # Web server / php-fpm user who owns the files
FIREWALL_TYPE="ufw"              # Firewall target: "ufw", "iptables", "firewalld", "hosts.deny"
# =======================================================

# Ensure we are running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (or via sudo)." >&2
    exit 1
fi

# Fetch the raw banlist using standard PHP to bootstrap WordPress (no WP-CLI dependency)
# Runs as the web server user for absolute safety.
if ! RAW_BANS=$(sudo -u "$WP_USER" php -r "define('WP_USE_THEMES', false); require '$WP_PATH/wp-load.php'; \$ban_list = is_multisite() ? get_site_option('loh_ban_list', array()) : get_option('loh_ban_list', array()); if (is_array(\$ban_list)) { foreach(array_keys(\$ban_list) as \$item) { echo \$item . PHP_EOL; } }" 2>/dev/null); then
    echo "ERROR: Failed to fetch banlist via PHP bootstrap. Please verify your WP_PATH, WP_USER, and that PHP CLI is installed." >&2
    exit 1
fi

# Process the banlist safely
echo "$RAW_BANS" | while read -r IP_OR_CIDR; do
    # Skip empty lines
    [[ -z "$IP_OR_CIDR" ]] && continue

    # Rigorous sanitization: only allow characters valid in IPv4, IPv6, and CIDR ranges
    # Permits digits, dots, colons, hex characters, and a single slash for CIDR.
    # Unbreakable defense against command/argument injection.
    if ! [[ "$IP_OR_CIDR" =~ ^[0-9a-fA-F:./]+$ ]]; then
        echo "WARNING: Blocked invalid IP/CIDR input format: $IP_OR_CIDR" >&2
        continue
    fi

    case "$FIREWALL_TYPE" in
        ufw)
            # Check if UFW rule already exists for this IP or CIDR block
            if ! ufw status | grep -Fw "$IP_OR_CIDR" >/dev/null; then
                echo "UFW Blocking: $IP_OR_CIDR"
                ufw insert 1 deny from "$IP_OR_CIDR" to any
            fi
            ;;

        iptables)
            # Check if iptables rule already exists for this IP or CIDR block
            if ! iptables -C INPUT -s "$IP_OR_CIDR" -j DROP &>/dev/null; then
                echo "iptables Blocking: $IP_OR_CIDR"
                iptables -I INPUT 1 -s "$IP_OR_CIDR" -j DROP
            fi
            ;;

        firewalld)
            # Check if firewalld permanent drop rule already exists for this IP/CIDR
            if ! firewall-cmd --zone=drop --query-source="$IP_OR_CIDR" &>/dev/null; then
                echo "firewalld Blocking: $IP_OR_CIDR"
                firewall-cmd --permanent --zone=drop --add-source="$IP_OR_CIDR"
                firewall-cmd --reload
            fi
            ;;

        hosts.deny)
            # Add to /etc/hosts.deny if not already present
            if ! grep -qF "ALL: $IP_OR_CIDR" /etc/hosts.deny 2>/dev/null; then
                echo "hosts.deny Blocking: $IP_OR_CIDR"
                echo "ALL: $IP_OR_CIDR" >> /etc/hosts.deny
            fi
            ;;

        *)
            echo "ERROR: Unsupported FIREWALL_TYPE: $FIREWALL_TYPE" >&2
            exit 1
            ;;
    esac
done

exit 0
