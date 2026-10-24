# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#          MOBSF USER CONFIGURATIONS
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# -------------------------
# STATIC ANALYZER SETTINGS
# -------------------------

# ==========ANDROID SKIP CLASSES==========================
# Common third party classes/paths that will be skipped
# during static analysis
import os
SKIP_CLASS_PATH = {
'com/google/', 'androidx', 'okhttp2/', 'okhttp3/',
'com/android/', 'com/squareup', 'okhttp/',
'android/content/', 'com/twitter/', 'twitter4j/',
'android/support/', 'org/apache/', 'oauth/signpost',
'android/arch', 'org/chromium/', 'com/facebook',
'org/spongycastle', 'org/bouncycastle',
'com/amazon/identity/', 'io/fabric/sdk',
'com/instabug', 'com/crashlytics/android',
'kotlinx/', 'kotlin/',
}
# Disable CVSSV2 Score by default
CVSS_SCORE_ENABLED = bool(os.getenv('MOBSF_CVSS_SCORE_ENABLED', ''))
# NIAP Scan
NIAP_ENABLED = os.getenv('MOBSF_NIAP_ENABLED', '')
# Permission to Code Mapping
PERM_MAPPING_ENABLED = os.getenv('MOBSF_PERM_MAPPING_ENABLED', '1')
# Dex 2 Smali Conversion
DEX2SMALI_ENABLED = os.getenv('MOBSF_DEX2SMALI_ENABLED', '1')
# Android Shared Object Binary Analysis
SO_ANALYSIS_ENABLED = os.getenv('MOBSF_SO_ANALYSIS_ENABLED', '1')
# iOS Dynamic Library Binary Analysis
DYLIB_ANALYSIS_ENABLED = os.getenv('MOBSF_DYLIB_ANALYSIS_ENABLED', '1')
# =================================================
# --------------------------
# MALWARE ANALYZER SETTINGS
# --------------------------

DOMAIN_MALWARE_SCAN = os.getenv('MOBSF_DOMAIN_MALWARE_SCAN', '1')
APKID_ENABLED = os.getenv('MOBSF_APKID_ENABLED', '1')
# ==================================================
# ======WINDOWS STATIC ANALYSIS SETTINGS ===========
# Private key
WINDOWS_VM_SECRET = os.getenv(
'MOBSF_WINDOWS_VM_SECRET', 'mobsf/MobSF/windows_vm_priv_key.asc')
# IP and Port of the MobSF Windows VM
# example: WINDOWS_VM_IP = '127.0.0.1'   ;noqa E800
WINDOWS_VM_IP = os.getenv('MOBSF_WINDOWS_VM_IP')
WINDOWS_VM_PORT = os.getenv('MOBSF_WINDOWS_VM_PORT', '8000')
# ==================================================

# ==============3rd Party Tools=====================
"""
If you want to use a different version of 3rd party tools used by MobSF.
You can do that by specifying the path here. If specified, MobSF will run
the tool from this location.
"""

# Android 3P Tools
BUNDLE_TOOL = os.getenv('MOBSF_BUNDLE_TOOL', '')
JADX_BINARY = os.getenv('MOBSF_JADX_BINARY', '')
BACKSMALI_BINARY = os.getenv('MOBSF_BACKSMALI_BINARY', '')
VD2SVG_BINARY = os.getenv('MOBSF_VD2SVG_BINARY', '')
APKTOOL_BINARY = os.getenv('MOBSF_APKTOOL_BINARY', '')
ADB_BINARY = os.getenv('MOBSF_ADB_BINARY', '')
AAPT2_BINARY = os.getenv('MOBSF_AAPT2_BINARY', '')
AAPT_BINARY = os.getenv('MOBSF_AAPT_BINARY', '')

# iOS 3P Tools
JTOOL_BINARY = os.getenv('MOBSF_JTOOL_BINARY', '')
CLASSDUMP_BINARY = os.getenv('MOBSF_CLASSDUMP_BINARY', '')
CLASSDUMP_SWIFT_BINARY = os.getenv('MOBSF_CLASSDUMP_SWIFT_BINARY', '')

# COMMON
JAVA_DIRECTORY = os.getenv('MOBSF_JAVA_DIRECTORY', '')

"""
Examples:
JAVA_DIRECTORY = 'C:/Program Files/Java/jdk1.7.0_17/bin/'
JAVA_DIRECTORY = '/usr/bin/'
JADX_BINARY = 'C:/Users/Ajin/AppData/Local/Programs/jadx/bin/jadx.bat'
JADX_BINARY = '/Users/ajin/jadx/bin/jadx'
"""
# ==========================================================
# -------------------------
# DYNAMIC ANALYZER SETTINGS
# -------------------------

# =======ANDROID DYNAMIC ANALYSIS SETTINGS===========
ANALYZER_IDENTIFIER = os.getenv('MOBSF_ANALYZER_IDENTIFIER', '')
FRIDA_TIMEOUT = int(os.getenv('MOBSF_FRIDA_TIMEOUT', '4'))
ACTIVITY_TESTER_SLEEP = int(os.getenv('MOBSF_ACTIVITY_TESTER_SLEEP', '4'))
# ==============================================

# ================HTTPS PROXY ===============
PROXY_IP = os.getenv('MOBSF_PROXY_IP', '127.0.0.1')
PROXY_PORT = int(os.getenv('MOBSF_PROXY_PORT', '1337'))
# ===================================================

# ========UPSTREAM PROXY SETTINGS ==============
# If you are behind a Proxy
UPSTREAM_PROXY_ENABLED = bool(os.getenv(
'MOBSF_UPSTREAM_PROXY_ENABLED', ''))
UPSTREAM_PROXY_SSL_VERIFY = os.getenv(
'MOBSF_UPSTREAM_PROXY_SSL_VERIFY', '1')
UPSTREAM_PROXY_TYPE = os.getenv('MOBSF_UPSTREAM_PROXY_TYPE', 'http')
UPSTREAM_PROXY_IP = os.getenv('MOBSF_UPSTREAM_PROXY_IP', '127.0.0.1')
UPSTREAM_PROXY_PORT = int(os.getenv('MOBSF_UPSTREAM_PROXY_PORT', '3128'))
UPSTREAM_PROXY_USERNAME = os.getenv('MOBSF_UPSTREAM_PROXY_USERNAME', '')
UPSTREAM_PROXY_PASSWORD = os.getenv('MOBSF_UPSTREAM_PROXY_PASSWORD', '')
# ==============================================

# ========DISABLED BY DEFAULT COMPONENTS=========
# Get AppMonsta API from https://appmonsta.com/dashboard/get_api_key/
APPMONSTA_API = os.getenv('MOBSF_APPMONSTA_API', '')
# ----------VirusTotal (API v3)-----------------
VT_ENABLED = bool(os.getenv('MOBSF_VT_ENABLED', ''))
VT_API_KEY = os.getenv('MOBSF_VT_API_KEY', '')
VT_UPLOAD = bool(os.getenv('MOBSF_VT_UPLOAD', ''))
# Before setting VT_ENABLED to True,
# Make sure VT_API_KEY is set to your VirusTotal API key
# register at: https://www.virustotal.com/#/join-us
# You can get your API KEY from:
# https://www.virustotal.com/gui/user/<username>/apikey/
# Files will be uploaded to VirusTotal if VT_UPLOAD is True.
# Files <=32MB use /files; larger files use /files/upload_url
# (up to 650MB).
# ===============================================
# =======IOS DYNAMIC ANALYSIS SETTINGS===========
# Should be SSH IP:PORT, example: 192.168.1.100:22
# Field also supports multiple devices, example: 192.168.1.100:22,192.168.1.101:22
IOS_ANALYZER_IDENTIFIERS = os.getenv('MOBSF_IOS_ANALYZER_IDENTIFIERS', '')
# SSH credentials for jailbroken iOS device (USB or WiFi path)
# Defaults match the standard jailbreak SSH default (root/alpine)
IOS_SSH_USER = os.getenv('MOBSF_IOS_SSH_USER', 'root')
IOS_SSH_PASSWORD = os.getenv('MOBSF_IOS_SSH_PASSWORD', 'alpine')
# ==============================================

# =======IOS DYNAMIC ANALYSIS CORELLIUM SETTINGS===========
CORELLIUM_API_DOMAIN = os.getenv('MOBSF_CORELLIUM_API_DOMAIN', '')
CORELLIUM_API_KEY = os.getenv('MOBSF_CORELLIUM_API_KEY', '')
CORELLIUM_PROJECT_ID = os.getenv('MOBSF_CORELLIUM_PROJECT_ID', '')
# CORELLIUM_PROJECT_ID is optional, MobSF will use any available project id
# ===============================================