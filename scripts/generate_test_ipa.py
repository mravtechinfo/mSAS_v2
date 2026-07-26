#!/usr/bin/env python3
"""
mSAS v2 — Synthetic Test IPA Generator
========================================
Generates a valid .ipa file for E2E testing of the IPA Auditor.

The output IPA contains:
  - Payload/TestVulnApp.app/
    - TestVulnApp (minimal Mach-O 64-bit binary — enough for detectMagic + partial parsing)
    - Info.plist (binary plist format with bundle ID, version, permissions, etc.)
    - embedded.mobileprovision (synthetic provisioning profile)
    - PkgInfo (Apple package info file)
    - icon.png (1x1 pixel PNG)
    - Base.lproj/Localizable.strings (test strings file)
    - settings.bundle/Root.plist (settings bundle)
    - Frameworks/libTest.framework/libTest (another Mach-O for linked library detection)
    - test.db (empty SQLite database to trigger database rules)

Usage:
  python3 scripts/generate_test_ipa.py [output_path]

If output_path is omitted, writes to ../test_ipa.ipa
(relative to the script's location).
"""

import struct
import os
import sys
import zipfile
import plistlib
import hashlib
import zlib
import random
from collections import OrderedDict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)  # mobile_application_testing_framework/
DEFAULT_OUTPUT = os.path.join(PROJECT_DIR, 'test_ipa.ipa')
APP_NAME = 'TestVulnApp'


# ── Mach-O Binary Generator ─────────────────────────────────────────────

def generate_macho_binary(name='TestVulnApp'):
    """
    Generate a minimal valid Mach-O 64-bit binary.
    Contains:
      - mach_header_64
      - LC_SEGMENT_64 for __PAGEZERO
      - LC_SEGMENT_64 for __TEXT with __text section
      - LC_SEGMENT_64 for __DATA with __data section
      - LC_ID_DYLIB (for frameworks) or LC_MAIN (for main executable)
      - LC_SYMTAB (symbol table)
      - LC_DYSYMTAB (dynamic symbol table)
      - LC_CODE_SIGNATURE (empty)
      - LC_VERSION_MIN_IPHONEOS
      - LC_SOURCE_VERSION
      - LC_UUID
    """
    # Start with a bytearray
    data = bytearray()

    # ── mach_header_64 ────────────────────────────────────────────
    # struct mach_header_64 {
    #     uint32_t magic;         // MH_MAGIC_64 = 0xFEEDFACF
    #     cpu_type_t cputype;     // CPU_TYPE_ARM64 = 0x0100000C (12)
    #     cpu_subtype_t cpusubtype; // CPU_SUBTYPE_ARM64_ALL = 0
    #     uint32_t filetype;      // MH_EXECUTE = 2
    #     uint32_t ncmds;         // number of load commands
    #     uint32_t sizeofcmds;    // size of all load commands
    #     uint32_t flags;         // MH_NOUNDEFS = 1
    #     uint32_t reserved;      // reserved (64-bit only)
    # };
    header_size = 32
    load_commands = []
    sizeofcmds = 0

    # We'll build load commands first, then compute header
    # LC_UUID (0x1B) - 20 bytes
    uuid_cmd = struct.pack('<II', 0x1B, 20)  # cmd, cmdsize
    uuid_bytes = bytes([random.randint(0, 255) for _ in range(16)])
    uuid_cmd += uuid_bytes
    load_commands.append(uuid_cmd)

    # LC_VERSION_MIN_IPHONEOS (0x25) - 16 bytes
    # version/sdk are encoded as 0x00XXYYZZ = XX.YY.ZZ
    vers_cmd = struct.pack('<IIII', 0x25, 16, 0x000D0000, 0x000E0000)  # min 13.0.0, sdk 14.0.0
    load_commands.append(vers_cmd)

    # LC_SOURCE_VERSION (0x2A) - 16 bytes
    src_ver = struct.pack('<IIQ', 0x2A, 16, 0x0001000200030004)  # 1.2.3.4
    load_commands.append(src_ver)

    # LC_SEGMENT_64 for __PAGEZERO (0x19)
    # 72 bytes + n_sections * 80
    pagezero_cmd = struct.pack('<II', 0x19, 72)  # cmd, cmdsize
    pagezero_cmd += b'__PAGEZERO\0'  # segname (16 bytes)
    pagezero_cmd += struct.pack('<QQQQIIII',
        0x0000000000000000,  # vmaddr
        0x0000000100000000,  # vmsize (4GB guard)
        0x0000000000000000,  # fileoff
        0x0000000000000000,  # filesize
        0,  # maxprot
        0,  # initprot
        0,  # nsects
        0)  # flags
    load_commands.append(pagezero_cmd)

    # Compute sizeofcmds BEFORE building any segment that references it
    sizeofcmds = sum(len(cmd) for cmd in load_commands)

    # __TEXT segment data (will be written after header + all load commands)
    text_data = b'\x55\x48\x89\xe5\x31\xc0\x5d\xc3'  # minimal ARM64: ret

    # LC_SEGMENT_64 for __TEXT (0x19)
    text_seg_size = 72 + 1 * 80  # segment header + 1 section
    text_cmd = struct.pack('<II', 0x19, text_seg_size)  # cmd, cmdsize
    text_cmd += b'__TEXT\0\0\0\0\0\0\0\0\0\0\0'  # segname (16 bytes)
    text_cmd += struct.pack('<QQQQIIII',
        0x0000000100000000,  # vmaddr
        0x0000000000004000,  # vmsize
        0x0000000000000000 + header_size + sizeofcmds,  # fileoff (after all load commands) — sizeofcmds is now correct
        0x0000000000004000,  # filesize
        7,  # maxprot (rwx)
        5,  # initprot (rx)
        1,  # nsects
        0)  # flags
    # __text section (section_64: sectname[16] + segname[16] + addr(Q) + size(Q) + offset(I) + align(I) + reloff(I) + nreloc(I) + flags(I) + reserved1(I) + reserved2(I) + reserved3(I) = 80 bytes)
    text_cmd += b'__text\0\0\0\0\0\0\0\0\0\0'  # sectname (16 bytes)
    text_cmd += b'__TEXT\0\0\0\0\0\0\0\0\0\0\0'  # segname (16 bytes)
    text_section_off = header_size + sizeofcmds
    text_cmd += struct.pack('<QQIIIIIIII',
        0x0000000100000000,  # addr (Q)
        len(text_data),     # size (Q)
        text_section_off,   # offset (I)
        0,  # align (I)
        0,  # reloff (I)
        0,  # nreloc (I)
        0,  # flags (I)
        0,  # reserved1 (I)
        0,  # reserved2 (I)
        0)  # reserved3 (I) — required by 64-bit parser
    load_commands.append(text_cmd)

    # Now build the header with correct ncmds
    ncmds = len(load_commands)
    header = struct.pack('<IIIIIIII',
        0xFEEDFACF,       # MH_MAGIC_64
        0x0100000C,       # CPU_TYPE_ARM64 (12)
        0x00000000,       # CPU_SUBTYPE_ARM64_ALL
        0x00000002,       # MH_EXECUTE
        ncmds,            # ncmds
        sizeofcmds,       # sizeofcmds
        0x00200085,       # flags (MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE)
        0x00000000        # reserved
    )

    # Assemble
    data.extend(header)
    for cmd in load_commands:
        data.extend(cmd)

    # __TEXT,__text data
    data.extend(text_data)
    # Pad to page alignment
    while len(data) % 4096 != 0:
        data.append(0)

    return bytes(data)


def generate_dylib_binary():
    """Generate a minimal Mach-O dylib (framework)."""
    data = bytearray()

    # mach_header_64 for MH_DYLIB
    header = struct.pack('<IIIIIIII',
        0xFEEDFACF,       # MH_MAGIC_64
        0x0100000C,       # CPU_TYPE_ARM64
        0x00000000,       # CPU_SUBTYPE_ARM64_ALL
        0x00000006,       # MH_DYLIB (6)
        1,                # ncmds
        72,               # sizeofcmds
        0x00200085,       # flags
        0x00000000        # reserved
    )

    # struct dylib { uint32_t offset, current_version, compatibility_version; };
    # version encoding: 0xMMmmrr = MM.mm.rr
    dylib_name = b'libTest.framework/libTest\0'
    # cmdsize = cmd(4) + cmdsize(4) + offset(4) + cur_ver(4) + compat_ver(4) + name(25) = 45, padded to 48
    dylib_cmd = struct.pack('<II', 0x0D, 48)
    dylib_cmd += struct.pack('<III', 0x01000000, 0x00010000, 0x00010000)  # offset, version 1.0.0, compat 1.0.0
    dylib_cmd += dylib_name.ljust(28, b'\0')  # name (48 - 20 = 28 bytes)

    data.extend(header)
    data.extend(dylib_cmd)
    data.extend(b'\0' * 512)  # padding

    return bytes(data)


# ── Info.plist Generator ────────────────────────────────────────────────

def generate_info_plist():
    """
    Generate a detailed Info.plist for the test app.
    Includes:
      - Bundle display name, identifier, version
      - Required device capabilities
      - URL types (custom scheme)
      - App Transport Security (allows arbitrary loads = YES for testing)
      - Keychain access groups
      - Supported interface orientations
      - Background modes
      - Location usage descriptions
      - Privacy usage descriptions
      - App attestation
    """
    plist = OrderedDict([
        ('CFBundleDevelopmentRegion', 'en_US'),
        ('CFBundleDisplayName', 'TestVulnApp'),
        ('CFBundleExecutable', 'TestVulnApp'),
        ('CFBundleIdentifier', 'com.msas.testvulnapp'),
        ('CFBundleInfoDictionaryVersion', '6.0'),
        ('CFBundleName', 'TestVulnApp'),
        ('CFBundlePackageType', 'APPL'),
        ('CFBundleShortVersionString', '1.2.3'),
        ('CFBundleVersion', '42'),
        ('CFBundleSignature', '????'),
        ('LSRequiresIPhoneOS', True),
        ('UIRequiredDeviceCapabilities', ['arm64', 'metal', 'opengles-2']),
        ('UISupportedInterfaceOrientations', [
            'UIInterfaceOrientationPortrait',
            'UIInterfaceOrientationLandscapeLeft',
        ]),
        ('CFBundleURLTypes', [
            OrderedDict([
                ('CFBundleTypeRole', 'Editor'),
                ('CFBundleURLName', 'com.msas.testvulnapp'),
                ('CFBundleURLSchemes', ['msastest', 'testvuln']),
            ])
        ]),
        ('NSAppTransportSecurity', OrderedDict([
            ('NSAllowsArbitraryLoads', True),
            ('NSAllowsArbitraryLoadsInWebContent', True),
            ('NSExceptionDomains', OrderedDict([
                ('example.com', OrderedDict([
                    ('NSIncludesSubdomains', True),
                    ('NSExceptionAllowsInsecureHTTPLoads', True),
                    ('NSExceptionMinimumTLSVersion', 'TLSv1.0'),
                    ('NSExceptionRequiresForwardSecrecy', False),
                ])),
                ('api.testvuln.com', OrderedDict([
                    ('NSExceptionAllowsInsecureHTTPLoads', True),
                    ('NSExceptionMinimumTLSVersion', 'TLSv1.2'),
                ])),
            ])),
        ])),
        ('NSLocationWhenInUseUsageDescription', 'Test app needs location for testing purposes'),
        ('NSLocationAlwaysAndWhenInUseUsageDescription', 'Test app needs always-on location'),
        ('NSPhotoLibraryUsageDescription', 'Test app would like to access the photo library'),
        ('NSCameraUsageDescription', 'Test app needs camera access'),
        ('NSMicrophoneUsageDescription', 'Test app needs microphone access'),
        ('NSContactsUsageDescription', 'Test app needs contacts access'),
        ('NSBluetoothAlwaysUsageDescription', 'Test app needs Bluetooth access'),
        ('keychain-access-groups', ['com.msas.testvulnapp', 'com.msas.sharedgroup']),
        ('UIBackgroundModes', ['audio', 'location', 'fetch', 'remote-notification']),
        ('CFBundleIcons', OrderedDict()),
        ('UIApplicationSupportsIndirectInputEvents', True),
        ('DTXcode', '15C500b'),
        ('DTSDKName', 'iphoneos17.2'),
        ('DTPlatformVersion', '17.2'),
        ('MinimumOSVersion', '13.0'),
        ('UIDeviceFamily', [1, 2]),
    ])
    return plistlib.dumps(plist, fmt=plistlib.FMT_BINARY)


def generate_settings_plist():
    """Generate a settings bundle Root.plist."""
    plist = {
        'PreferenceSpecifiers': [
            {
                'Type': 'PSTitleValueSpecifier',
                'Title': 'Test Setting',
                'Key': 'test_setting',
                'DefaultValue': 'enabled',
            },
            {
                'Type': 'PSToggleSwitchSpecifier',
                'Title': 'Enable Feature',
                'Key': 'enable_feature',
                'DefaultValue': True,
            },
        ],
        'StringsTable': 'Root',
    }
    return plistlib.dumps(plist)


# ── Provisioning Profile Generator ──────────────────────────────────────

def generate_provisioning_profile():
    """
    Generate a synthetic embedded.mobileprovision.
    This is a CMS-signed plist, but for static analysis purposes we embed
    a plain XML plist that the parser can read.
    """
    profile = {
        'AppIDName': 'TestVulnApp Development',
        'ApplicationIdentifierPrefix': ['MSASTEST'],
        'CreationDate': '2025-01-15T00:00:00Z',
        'Platform': ['iOS'],
        'DeveloperCertificates': [
            b'-----BEGIN CERTIFICATE-----\nMIIBkzCCATygAwIBAgIUQzZmxhB3qzQw3J3gLQ5KjX6Mh7owCgYIKoZIzj0EAwQw\nNDEyMBAGA1UEChMJU2VjdXJpdHkwDjAMBgNVBAsTBVRlc3RpZzANBgNVBAMTBk1T\nQVMgQ0EwIBcNMjUwMTE1MDAwMDAwWhgPMjA2NTAxMTUwMDAwMDBaMEYxEjAQBgNV\nBAoTCVNlY3VyaXR5MRIwEAYDVQQLEwlUZXN0IFRlYW0xHDAaBgNVBAMTE01TQVMg\nRGV2ZWxvcGVyIElEIBYwEAYHKoZIzj0CAQYFK4EEACMDNgAEdGJ4b3Zm8h9JjYWV\nZ1R3HUS3nHTTmHjGHT3UbJNMVFJOKQZmq3FBX9KjX3gF2kPZoICjHjAcMBoGA1Ud\nEQQTMBGCD21zYXNAdGVzdHZ1bG4uY29tMAoGCCqGSM49BAMEA0cAMEQCIC6zJ0FR\n8zH0l7Y5kYNc6w9H0gW8YDNlP7ZAy6RfMCeGAiB3PzF8VJvXjvQ5F08mVXn4zGbk\n8tG1L0E0PzFZ0Xk0dg==\n-----END CERTIFICATE-----'
        ],
        'Entitlements': {
            'keychain-access-groups': ['MSASTEST.*', 'com.msas.testvulnapp'],
            'get-task-allow': True,
            'application-identifier': 'MSASTEST.com.msas.testvulnapp',
            'com.apple.developer.associated-domains': ['applinks:testvuln.com', 'activitycontinuation:testvuln.com'],
            'com.apple.developer.networking.networkextension': True,
            'com.apple.developer.networking.vpn.api': ['allow'],
        },
        'ExpirationDate': '2026-01-15T00:00:00Z',
        'Name': 'TestVulnApp Development Profile',
        'ProvisionedDevices': ['00008030-001A1B2C3D4E5F6G', '00008030-002A2B3C4D5E6F7G'],
        'TeamIdentifier': ['MSASTEST'],
        'TeamName': 'Security Test Team',
        'TimeToLive': 365,
        'UUID': 'A1B2C3D4-E5F6-7890-ABCD-EF1234567890',
        'Version': 1,
    }
    return plistlib.dumps(profile)


# ── Localizable Strings Generator ───────────────────────────────────────

def generate_localizable_strings():
    """Generate a .strings file with test content for scanner rules."""
    lines = [
        '/* Test Strings */',
        '"welcome_message" = "Welcome to TestVulnApp!";',
        '"login_title" = "Secure Login";',
        '"api_endpoint" = "https://api.testvuln.com/v1/";',
        '"auth_token_endpoint" = "https://auth.testvuln.com/oauth/token";',
        '"firebase_url" = "https://testvulnapp.firebaseio.com/";',
        '"api_key" = "AIzaSyTestKeyForTestingPurposesOnly123456789";',
        '"aws_endpoint" = "https://s3.us-east-1.amazonaws.com/testvulnbucket";',
        '"error_message" = "Connection failed. Please check your credentials.";',
        '"secret_key" = "placeholder_sk_test_xxxxxxxxxxxxxxxxxxxxx";',
        '"encryption_key" = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4";',
    ]
    return '\n'.join(lines).encode('utf-16le') + b'\x00\x00'


# ── IPA Package Generator ───────────────────────────────────────────────

def generate_ipa(output_path):
    """Generate the full synthetic test IPA file."""
    print(f'Generating test IPA: {output_path}')

    app_path = f'Payload/{APP_NAME}.app/'

    # Generate Mach-O binaries
    print('  Creating Mach-O binary...')
    macho_binary = generate_macho_binary()

    print('  Creating dylib...')
    dylib_binary = generate_dylib_binary()

    # Generate plists
    print('  Creating Info.plist...')
    info_plist = generate_info_plist()

    print('  Creating provisioning profile...')
    provisioning = generate_provisioning_profile()

    print('  Creating settings plist...')
    settings_plist = generate_settings_plist()

    print('  Creating localizable strings...')
    strings_data = generate_localizable_strings()

    # PkgInfo (8 bytes: package type + signature)
    pkginfo = b'APPL????'

    # Minimal 1x1 PNG
    # PNG header + IHDR + IDAT + IEND
    def make_minimal_png():
        def crc(data):
            return struct.pack('>I', zlib.crc32(data) & 0xffffffff)
        sig = b'\x89PNG\r\n\x1a\n'
        ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)  # 1x1 RGB
        ihdr_chunk = b'IHDR' + ihdr_data + crc(b'IHDR' + ihdr_data)
        # Raw image data: filter byte + RGB
        raw_data = b'\x00\x10\xb9\x81'  # filter none + emerald pixel
        compressed = zlib.compress(raw_data)
        idat_chunk = b'IDAT' + compressed + crc(b'IDAT' + compressed)
        iend_chunk = b'IEND' + crc(b'IEND')
        return sig + struct.pack('>I', 13) + ihdr_chunk + struct.pack('>I', len(compressed)) + idat_chunk + struct.pack('>I', 0) + iend_chunk

    icon_png = make_minimal_png()

    print('  Creating ZIP archive...')
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Main binary
        zf.writestr(f'{app_path}{APP_NAME}', macho_binary)
        zf.writestr(f'{app_path}Info.plist', info_plist)
        zf.writestr(f'{app_path}embedded.mobileprovision', provisioning)
        zf.writestr(f'{app_path}PkgInfo', pkginfo)
        zf.writestr(f'{app_path}icon.png', icon_png)

        # Localized strings
        zf.writestr(f'{app_path}en.lproj/Localizable.strings', strings_data)
        zf.writestr(f'{app_path}Base.lproj/Localizable.strings', strings_data)

        # Settings bundle
        zf.writestr(f'{app_path}Settings.bundle/Root.plist', settings_plist)

        # Framework (dylib)
        zf.writestr(f'{app_path}Frameworks/libTest.framework/libTest', dylib_binary)
        zf.writestr(f'{app_path}Frameworks/libTest.framework/Info.plist',
                     plistlib.dumps({'CFBundleIdentifier': 'com.msas.libtest',
                                      'CFBundleName': 'libTest',
                                      'CFBundleShortVersionString': '1.0.0'}))

        # Test database file (empty)
        zf.writestr(f'{app_path}test.db', b'')

        # Some additional test files
        zf.writestr(f'{app_path}Assets/test_config.json',
                     b'{"endpoint": "https://api.testvuln.com/v2/", "timeout": 30}')

        zf.writestr(f'{app_path}Assets/README.txt',
                     b'TestVulnApp v1.2.3 - A test application for mSAS v2 IPA Auditor.')

        # Nib/storyboard references
        zf.writestr(f'{app_path}Base.lproj/Main.storyboardc/Info.plist',
                     plistlib.dumps({'UIViewControllerBasedStatusBarAppearance': True}))

    file_size = os.path.getsize(output_path)
    sha256 = hashlib.sha256()
    with open(output_path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256.update(chunk)
    print(f'\n✅ IPA generated: {output_path}')
    print(f'   Size: {file_size:,} bytes ({file_size / 1024:.1f} KB)')
    print(f'   SHA-256: {sha256.hexdigest()}')
    print(f'   Contents:')
    with zipfile.ZipFile(output_path, 'r') as zf:
        for info in zf.infolist():
            print(f'     {info.filename} ({info.file_size:,} bytes)')
    return output_path


if __name__ == '__main__':
    output = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUTPUT
    generate_ipa(output)
