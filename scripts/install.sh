#!/bin/sh
#
# Posea AD SSO pfSense Package Installer
# Installs Active Directory Single Sign-On (AD SSO) for pfSense
#

set -e

echo "=========================================================="
echo "    Posea AD SSO for pfSense - Installation Script       "
echo "=========================================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: This script must be run as root."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)"

if [ ! -d "${SCRIPT_DIR}/pfsense-pkg" ]; then
    echo "[*] Piped installer detected. Downloading repository files from GitHub..."
    TMP_DIR="/tmp/pfsense_ad_sso_install"
    rm -rf "${TMP_DIR}"
    mkdir -p "${TMP_DIR}"

    ARCHIVE_URL="https://codeload.github.com/bysinbin/pfsense-ad-sso/tar.gz/refs/heads/main"
    if ! fetch -q -o "${TMP_DIR}/main.tar.gz" "${ARCHIVE_URL}"; then
        fetch -q -o "${TMP_DIR}/main.tar.gz" "https://github.com/bysinbin/pfsense-ad-sso/archive/refs/heads/main.tar.gz"
    fi

    tar -xzf "${TMP_DIR}/main.tar.gz" -C "${TMP_DIR}"
    SCRIPT_DIR="${TMP_DIR}/pfsense-ad-sso-main"

    if [ ! -d "${SCRIPT_DIR}/pfsense-pkg" ]; then
        echo "[!] Error: Failed to unpack repository files."
        exit 1
    fi
    echo "[+] Repository files downloaded successfully."
fi

echo "[*] Step 1: Creating Working Directories..."
mkdir -p /var/etc/posea_ad_sso
mkdir -p /var/log
chmod 750 /var/etc/posea_ad_sso

echo "[*] Step 2: Installing FreeBSD rc.d Service..."
mkdir -p /usr/local/etc/rc.d
cp "${SCRIPT_DIR}/pfsense-pkg/etc/rc.d/posea_ad_sso.sh" /usr/local/etc/rc.d/posea_ad_sso.sh
chmod 755 /usr/local/etc/rc.d/posea_ad_sso.sh

echo "[*] Step 3: Installing pfSense Package & WebGUI Components..."
mkdir -p /usr/local/pkg
mkdir -p /usr/local/www

cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/pkg/posea_ad_sso.xml" /usr/local/pkg/posea_ad_sso.xml
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/pkg/posea_ad_sso.inc" /usr/local/pkg/posea_ad_sso.inc
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/pkg/posea_ad_ssod.php" /usr/local/pkg/posea_ad_ssod.php
if [ -f "${SCRIPT_DIR}/scripts/sso_client.php" ]; then
    cp "${SCRIPT_DIR}/scripts/sso_client.php" /usr/local/pkg/sso_client.php
    chmod 755 /usr/local/pkg/sso_client.php
fi

cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/www/posea_ad_sso_sessions.php" /usr/local/www/posea_ad_sso_sessions.php
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/www/posea_ad_sso_bindings.php" /usr/local/www/posea_ad_sso_bindings.php
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/www/posea_ad_sso_test.php" /usr/local/www/posea_ad_sso_test.php

chmod 644 /usr/local/pkg/posea_ad_sso.*
chmod 755 /usr/local/pkg/posea_ad_ssod.php
chmod 644 /usr/local/www/posea_ad_sso_*

echo "[*] Step 4: Registering Package in pfSense config.xml..."
php -r '
require_once("config.inc");
require_once("/usr/local/pkg/posea_ad_sso.inc");

$pkg_found = false;
if (isset($config["installedpackages"]["package"])) {
    foreach ($config["installedpackages"]["package"] as $pkg) {
        if ($pkg["name"] == "poseaadsso") {
            $pkg_found = true;
            break;
        }
    }
}

if (!$pkg_found) {
    $config["installedpackages"]["package"][] = [
        "name" => "poseaadsso",
        "descr" => "Active Directory Single Sign-On (AD SSO) for pfSense",
        "website" => "https://github.com/bysinbin/pfsense-ad-sso",
        "version" => "1.0.0",
        "status" => "Stable",
        "configurationfile" => "posea_ad_sso.xml"
    ];
    echo "[+] Registered poseaadsso package in config.xml\n";
} else {
    echo "[*] Package poseaadsso already registered\n";
}

$menu_found = false;
if (isset($config["installedpackages"]["menu"])) {
    foreach ($config["installedpackages"]["menu"] as $m) {
        if ($m["name"] == "Active Directory SSO") {
            $menu_found = true;
            break;
        }
    }
}
if (!$menu_found) {
    $config["installedpackages"]["menu"][] = [
        "name" => "Active Directory SSO",
        "section" => "Services",
        "url" => "/pkg_edit.php?xml=posea_ad_sso.xml"
    ];
    echo "[+] Registered Active Directory SSO in Services menu\n";
}
write_config("Installed Active Directory SSO package");

posea_ad_sso_install();
'

echo "[*] Step 5: Starting Posea AD SSO Service..."
/usr/local/etc/rc.d/posea_ad_sso.sh start || true

if [ -d "/tmp/pfsense_ad_sso_install" ]; then
    rm -rf "/tmp/pfsense_ad_sso_install"
fi

echo "=========================================================="
echo "  [SUCCESS] Posea AD SSO has been successfully installed! "
echo "  Access in pfSense WebGUI: Services > Active Directory SSO"
echo "=========================================================="
