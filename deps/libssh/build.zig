// Build wrapper for libssh.
//
// libssh is consumed as a pure-source dependency (see build.zig.zon): the
// upstream tree carries no build.zig of its own, so this file owns all of the
// build configuration while the library source comes from an unmodified
// upstream release tarball.
//
// libssh's crypto backend is mbedtls. We compile against Acton's mbedtls
// headers — located via the -Dacton_sysdeps build option from Build.act,
// pointing at the toolchain's <dist>/deps — but we do NOT link mbedtls
// here. The mbedtls objects are provided by Acton's base library at the final
// executable link; linking them here too would only duplicate symbols. Using
// the toolchain's own headers guarantees the ABI matches the mbedtls base links.
//
// zlib, which libssh needs for the zlib@openssh.com / zlib compression methods,
// follows the same split with the acton-zlib package as the supplier: this
// project depends on acton_zlib (see Build.act), whose ActonProject archive
// carries the zlib objects to the final executable link.
// We compile against the headers of the exact zlib source acton-zlib pins,
// reached through its wrapper's own dependency and injected as the
// -Dacton_zlib_src build option, so the zlib version is pinned in one place.

const builtin = @import("builtin");
const std = @import("std");


pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});
    const t = target.result;
    const with_server = b.option(bool, "WITH_SERVER", "Enable server-side APIs") orelse false;
    const has_pthread = (t.os.tag != .windows);
    // Absolute path to the Acton toolchain's bundled deps (<dist>/deps), injected
    // by Build.act from the Acton base dependency path. Used to find the mbedtls
    // headers libssh compiles against (must match the mbedtls that base links).
    // Empty only for a standalone `zig build` that does not use the crypto backend.
    const acton_sysdeps = b.option([]const u8, "acton_sysdeps", "Absolute path to the Acton toolchain deps dir (<dist>/deps)") orelse "";
    // Absolute path to the zlib source tree pinned by the acton-zlib package,
    // injected by Build.act. Headers only — the objects come from acton_zlib's
    // ActonProject at the final link (see top-of-file note).
    const acton_zlib_src = b.option([]const u8, "acton_zlib_src", "Absolute path to the zlib source tree pinned by acton-zlib") orelse "";

    const upstream = b.dependency("libssh_upstream", .{});

    var lib = b.addLibrary(.{
        .name = "ssh",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });

    const config_header = b.addConfigHeader(
        .{
            .style = .{ .cmake = upstream.path("config.h.cmake") },
            .include_path = "config.h",
        },
        .{
            .PACKAGE = "libssh",
            .VERSION = "0.12.2",
            .PROJECT_NAME = "libssh",
            .PROJECT_VERSION = "0.12.2",
            .SYSCONFDIR = "/etc",
            .BINARYDIR = "/usr/bin",
            .SOURCEDIR = ".",
            .GLOBAL_CONF_DIR = "/etc/ssh",
            .USR_GLOBAL_CONF_DIR = "/usr/etc/ssh",
            .GLOBAL_BIND_CONFIG = "/etc/ssh/libssh_server_config",
            .USR_GLOBAL_BIND_CONFIG = "/usr/etc/ssh/libssh_server_config",
            .GLOBAL_CLIENT_CONFIG = "/etc/ssh/ssh_config",
            .USR_GLOBAL_CLIENT_CONFIG = "/usr/etc/ssh/ssh_config",
            .HAVE_ARGP_H = true,
            .HAVE_ARPA_INET_H = true,
            .HAVE_IFADDRS_H = (t.os.tag != .windows),
            .HAVE_GLOB_H = true,
            .HAVE_VALGRIND_VALGRIND_H = false,
            .HAVE_PTY_H = true,
            .HAVE_UTMP_H = true,
            .HAVE_UTIL_H = true,
            .HAVE_LIBUTIL_H = true,
            .HAVE_SYS_TIME_H = true,
            .HAVE_SYS_UTIME_H = false,
            .HAVE_IO_H = true,
            .HAVE_TERMIOS_H = true,
            .HAVE_UNISTD_H = true,
            .HAVE_STDINT_H = true,
            .HAVE_OPENSSL_AES_H = false,
            .HAVE_WSPIAPI_H = true,
            .HAVE_BLOWFISH = false,
            .HAVE_OPENSSL_DES_H = false,
            .HAVE_OPENSSL_ECDH_H = false,
            .HAVE_OPENSSL_EC_H = false,
            .HAVE_OPENSSL_ECDSA_H = false,
            .HAVE_PTHREAD_H = has_pthread,
            .HAVE_OPENSSL_ECC = false,
            .HAVE_GCRYPT_ECC = false,
            .HAVE_ECC = true,
            .HAVE_GLOB_GL_FLAGS_MEMBER = true,
            .HAVE_GCRYPT_CHACHA_POLY = false,

            .HAVE_OPENSSL_EVP_CHACHA20 = false,
            .HAVE_OPENSSL_EVP_KDF_CTX = false,
            .HAVE_OPENSSL_FIPS_MODE = false,
            .HAVE_SNPRINTF = true,
            .HAVE__SNPRINTF = true,
            .HAVE__SNPRINTF_S = true,
            .HAVE_VSNPRINTF = true,
            .HAVE__VSNPRINTF = true,
            .HAVE__VSNPRINTF_S = true,
            .HAVE_ISBLANK = true,
            .HAVE_STRNCPY = true,
            .HAVE_STRNDUP = true,
            .HAVE_CFMAKERAW = true,
            .HAVE_GETADDRINFO = true,
            .HAVE_POLL = true,
            .HAVE_SELECT = true,
            .HAVE_CLOCK_GETTIME = true,
            .HAVE_NTOHLL = if (t.os.tag == .linux) false else true,
            .HAVE_HTONLL = if (t.os.tag == .linux) false else true,
            .HAVE_STRTOULL = true,
            .HAVE___STRTOULL = true,
            .HAVE__STRTOUI64 = true,
            .HAVE_GLOB = true,
            .HAVE_EXPLICIT_BZERO = false,
            .HAVE_MEMSET_S = if (t.os.tag == .linux) false else true,
            .HAVE_SECURE_ZERO_MEMORY = if (t.os.tag == .linux) false else true,
            .HAVE_CMOCKA_SET_TEST_FILTER = false,

            .HAVE_LIBCRYPTO = false,
            .HAVE_LIBGCRYPT = false,
            .HAVE_LIBMBEDCRYPTO = true,
            .HAVE_PTHREAD = has_pthread,
            .HAVE_CMOCKA = false,
            .HAVE_LIBFIDO2 = false,

            // Use the bundled fallback implementations for Curve25519 and
            // ML-KEM rather than crypto-backend-specific implementations.
            .HAVE_MBEDTLS_CURVE25519 = false,
            .HAVE_GCRYPT_CURVE25519 = false,
            .HAVE_GCRYPT_MLKEM = false,
            .HAVE_OPENSSL_MLKEM = false,
            .HAVE_MLKEM1024 = false,
            .HAVE_MEMSET_EXPLICIT = false,

            .HAVE_GCC_THREAD_LOCAL_STORAGE = false,
            .HAVE_MSC_THREAD_LOCAL_STORAGE = false,

            .HAVE_FALLTHROUGH_ATTRIBUTE = true,
            .HAVE_UNUSED_ATTRIBUTE = true,
            .HAVE_WEAK_ATTRIBUTE = true,

            .HAVE_CONSTRUCTOR_ATTRIBUTE = true,
            .HAVE_DESTRUCTOR_ATTRIBUTE = true,

            .HAVE_GCC_VOLATILE_MEMORY_PROTECTION = true,

            .HAVE_COMPILER__FUNC__ = true,
            .HAVE_COMPILER__FUNCTION__ = true,

            .HAVE_GCC_BOUNDED_ATTRIBUTE = false,
            .WITH_GSSAPI = false,
            .WITH_ZLIB = true,
            .WITH_FIDO2 = false,
            .WITH_SFTP = false,
            .WITH_SERVER = with_server,
            .WITH_EXEC = true,
            .WITH_GEX = true,
            .WITH_INSECURE_NONE = true,
            .WITH_BLOWFISH_CIPHER = false,
            .DEBUG_CRYPTO = false,
            .DEBUG_PACKET = false,
            .WITH_PCAP = false,
            .DEBUG_CALLTRACE = false,
            .WITH_NACL = false,
            .WITH_PKCS11_URI = true,
            .WITH_PKCS11_PROVIDER = true,

            .WORDS_BIGENDIAN = false,
        },
    );

    const version_header = b.addConfigHeader(.{
        .style = .{ .cmake = upstream.path("include/libssh/libssh_version.h.cmake") },
        .include_path = "libssh/libssh_version.h",
    }, .{
        .libssh_VERSION_MAJOR = 0,
        .libssh_VERSION_MINOR = 12,
        .libssh_VERSION_PATCH = 2,
    });

    lib.root_module.addConfigHeader(config_header);
    lib.root_module.addConfigHeader(version_header);

    var source_files = std.ArrayList([]const u8).empty;
    defer source_files.deinit(b.allocator);
    var flags = std.ArrayList([]const u8).empty;
    defer flags.deinit(b.allocator);

    flags.appendSlice(b.allocator, &.{
        "-Wall",
        "-Wextra",
        "-Wpedantic",
    }) catch unreachable;

    source_files.appendSlice(b.allocator, &.{
        "src/agent.c",
        "src/auth.c",
        "src/base64.c",
        "src/bignum.c",
        "src/buffer.c",
        "src/callbacks.c",
        "src/channels.c",
        "src/client.c",
        "src/config.c",
        "src/connect.c",
        "src/connector.c",
        "src/crypto_common.c",
        "src/curve25519.c",
        "src/dh.c",
        "src/ecdh.c",
        "src/error.c",
        "src/getpass.c",
        "src/gzip.c",
        "src/hybrid_mlkem.c",
        "src/init.c",
        "src/kdf.c",
        "src/kex.c",
        "src/known_hosts.c",
        "src/knownhosts.c",
        "src/legacy.c",
        "src/log.c",
        "src/match.c",
        "src/messages.c",
        "src/misc.c",
        "src/mlkem.c",
        "src/options.c",
        "src/packet.c",
        "src/packet_cb.c",
        "src/packet_crypt.c",
        "src/pcap.c",
        "src/pki.c",
        "src/pki_container_openssh.c",
        "src/pki_context.c",
        "src/poll.c",
        "src/session.c",
        "src/scp.c",
        "src/sntrup761.c",
        "src/socket.c",
        "src/string.c",
        "src/threads.c",
        "src/ttyopts.c",
        "src/wrapper.c",
        "src/external/bcrypt_pbkdf.c",
        "src/external/blowfish.c",
        "src/config_parser.c",
        "src/token.c",
        "src/pki_ed25519_common.c",
    }) catch unreachable;

    if (with_server) {
        source_files.appendSlice(b.allocator, &.{
            "src/server.c",
            "src/bind.c",
            "src/bind_config.c",
        }) catch unreachable;
    }

    if (t.os.tag != .windows) {
        source_files.appendSlice(b.allocator, &.{
            "src/threads/noop.c",
            "src/threads/pthread.c",
        }) catch unreachable;
    }

    // mbedtls crypto backend sources.
    source_files.appendSlice(b.allocator, &.{
        "src/threads/mbedtls.c",
        "src/libmbedcrypto.c",
        "src/mbedcrypto_missing.c",
        "src/pki_mbedcrypto.c",
        "src/ecdh_mbedcrypto.c",
        "src/getrandom_mbedcrypto.c",
        "src/md_mbedcrypto.c",
        "src/dh_key.c",
        "src/pki_ed25519.c",
        "src/external/ed25519.c",
        "src/external/fe25519.c",
        "src/external/ge25519.c",
        "src/external/sc25519.c",
        "src/external/chacha.c",
        "src/external/poly1305.c",
        "src/chachapoly.c",
        "src/external/sntrup761.c",
        "src/dh-gex.c",
        "src/external/curve25519_ref.c",
        "src/curve25519_fallback.c",
        "src/mlkem_native.c",
        "src/external/libcrux_mlkem768_sha3.c",
    }) catch unreachable;

    lib.root_module.addCSourceFiles(.{
        .root = upstream.path("."),
        .files = source_files.items,
        .flags = flags.items,
    });
    lib.root_module.addIncludePath(upstream.path("include"));
    // mbedtls headers only — the objects are linked via Acton's base at the final
    // executable link (see top-of-file note). acton_sysdeps points at the
    // toolchain's <dist>/deps; mbedtls headers live under mbedtls/include.
    if (acton_sysdeps.len > 0) {
        lib.root_module.addIncludePath(.{ .cwd_relative = b.pathJoin(&.{ acton_sysdeps, "mbedtls", "include" }) });
    }
    if (acton_zlib_src.len > 0) {
        lib.root_module.addIncludePath(.{ .cwd_relative = acton_zlib_src });
    }
    lib.root_module.link_libc = true;

    lib.installHeadersDirectory(upstream.path("include/libssh"), "libssh", .{});
    lib.installHeader(version_header.getOutputFile(), "libssh/libssh_version.h");

    b.installArtifact(lib);
}
