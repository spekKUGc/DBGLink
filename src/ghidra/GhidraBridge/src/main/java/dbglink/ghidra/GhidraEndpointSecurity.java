package dbglink.ghidra;

import java.io.IOException;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.google.gson.JsonObject;

import static dbglink.ghidra.GhidraBridgeServer.*;

/**
 * Endpoint-file and token handling.
 *
 * <p>Pinned-port + pinned-endpoint guidance (fail-closed): when both
 * {@code DBGLINK_GHIDRA_PORT} and {@code DBGLINK_GHIDRA_ENDPOINT} (or
 * {@code DBGLINK_GHIDRA_ENDPOINT_DIR}) are pinned, two bridge instances can
 * race on the same file and port, and a stale endpoint can outlive its owner.
 * Prefer the ephemeral default (no pin) unless the consumer verifies the
 * endpoint {@code pid} field before trusting {@code host}/{@code port}. The
 * bridge always overwrites the endpoint atomically and then restricts it to
 * the current user (owner + SYSTEM on Windows, 0600 on POSIX); when the
 * endpoint location is non-default and the restriction cannot be applied the
 * publication fails closed and the file is removed.</p>
 */
final class GhidraEndpointSecurity {

    static void writeEndpoint(Path endpointPath, int port, String token) throws IOException {
        if (endpointPath == null || endpointPath.getParent() == null) {
            throw new IOException("Ghidra endpoint path has no safe parent");
        }
        Path parent = endpointPath.getParent();
        ensureSafePath(parent);
        if (Files.exists(endpointPath, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isRegularFile(endpointPath, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Ghidra endpoint path is not a regular file");
        }
        JsonObject endpoint = new JsonObject();
        endpoint.addProperty("protocolVersion", PROTOCOL_VERSION);
        endpoint.addProperty("host", "127.0.0.1");
        endpoint.addProperty("port", port);
        endpoint.addProperty("pid", ProcessHandle.current().pid());
        endpoint.addProperty("token", token);
        byte[] content = JSON.toJson(endpoint).getBytes(StandardCharsets.UTF_8);
        Path temporaryPath = endpointPath.resolveSibling(
            endpointPath.getFileName() + ".tmp-" + UUID.randomUUID()
        );
        boolean published = false;
        try {
            // Create the file empty and restrict it BEFORE the token is
            // written. The endpoint carries the bridge token: writing first
            // and restricting afterwards leaves a window in which a local
            // user can read the published file.
            Files.createFile(temporaryPath);
            applyOwnerOnlyPermissionsOrFailClosed(temporaryPath);
            Files.write(
                temporaryPath,
                content,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING
            );
            // Revalidate both sides after creating the temporary file.  The
            // endpoint directory and target are attacker-controlled filesystem
            // objects when the bridge is launched outside the default profile.
            ensureSafePath(parent);
            if (Files.exists(endpointPath, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isRegularFile(endpointPath, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("Ghidra endpoint path is not a regular file");
            }
            try {
                Files.move(
                    temporaryPath,
                    endpointPath,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING
                );
            }
            catch (java.nio.file.AtomicMoveNotSupportedException exception) {
                Files.move(temporaryPath, endpointPath, StandardCopyOption.REPLACE_EXISTING);
            }
            published = true;
            ensureSafePath(endpointPath);
            // SEC-C J1: mirror the native pipe's user-only DACL. Restrict the
            // published endpoint (which carries the auth token) to the owner
            // after the atomic move; fail closed when non-default (see below).
            applyOwnerOnlyPermissionsOrFailClosed(endpointPath);
        }
        catch (IOException | RuntimeException exception) {
            if (published && isSafePath(endpointPath)) {
                try {
                    Files.deleteIfExists(endpointPath);
                }
                catch (IOException ignored) {
                    // Preserve the original publication failure.
                }
            }
            throw exception;
        }
        finally {
            try {
                Files.deleteIfExists(temporaryPath);
            }
            catch (IOException ignored) {
                // Preserve the original endpoint publication failure.
            }
        }
    }

    static Path createEndpointPath() throws IOException {
        String configured = System.getenv("DBGLINK_GHIDRA_ENDPOINT");
        if (configured != null && !configured.isBlank()) {
            Path path = Path.of(configured).toAbsolutePath().normalize();
            if (path.getParent() != null) {
                ensureSafePath(path.getParent());
                Files.createDirectories(path.getParent());
                ensureSafePath(path.getParent());
            }
            if (Files.exists(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("configured Ghidra endpoint is not a regular file");
            }
            return path;
        }

        String configuredDirectory = System.getenv("DBGLINK_GHIDRA_ENDPOINT_DIR");
        Path directory = configuredDirectory == null || configuredDirectory.isBlank()
            ? Path.of(System.getProperty("java.io.tmpdir"), "DbgLink")
            : Path.of(configuredDirectory);
        ensureSafePath(directory);
        Files.createDirectories(directory);
        ensureSafePath(directory);
        return directory.resolve(
            "ghidra-bridge-" + ProcessHandle.current().pid() + "-" + UUID.randomUUID() + ".json"
        );
    }

    private static void ensureSafePath(Path path) throws IOException {
        // Residual TOCTOU: this validates the path at check time; an attacker
        // with write access to a non-default endpoint directory could swap a
        // component between validation and open. The bridge revalidates after
        // creating the temp file and after the atomic move, and fails closed
        // on permission errors when non-default. A full open-by-handle fix
        // (O_NOFOLLOW per-component traversal) is a documented follow-up.
        Path current = path.toAbsolutePath().normalize();
        while (current != null) {
            if (Files.isSymbolicLink(current)) {
                throw new IOException("Ghidra endpoint path contains a symbolic link");
            }
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                BasicFileAttributes attributes = Files.readAttributes(
                    current,
                    BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS
                );
                if (attributes.isOther()) {
                    throw new IOException("Ghidra endpoint path contains an unsupported reparse point");
                }
            }
            current = current.getParent();
        }
    }

    static boolean isSafePath(Path path) {
        try {
            ensureSafePath(path);
            return true;
        }
        catch (IOException | RuntimeException exception) {
            return false;
        }
    }

    static int readPort() throws IOException {
        String value = System.getenv("DBGLINK_GHIDRA_PORT");
        if (value == null || value.isBlank()) {
            return 0;
        }
        try {
            int port = Integer.parseInt(value.trim());
            if (port < 0 || port > 65_535) {
                throw new NumberFormatException();
            }
            return port;
        }
        catch (NumberFormatException exception) {
            throw new IOException("DBGLINK_GHIDRA_PORT is outside 0..65535");
        }
    }

    static String readToken() throws IOException {
        String configured = System.getenv("DBGLINK_GHIDRA_TOKEN");
        if (configured != null && !configured.isBlank()) {
            String value = configured.trim();
            // SEC-C J6: operator-pinned tokens must be at least 32 chars.
            // 16 chars are brute-forceable when the endpoint file is exposed;
            // the random token below is 43 base64url chars (256 bits).
            if (value.length() < 32 || value.length() > MAX_TOKEN_CHARS ||
                value.chars().anyMatch(Character::isISOControl)) {
                throw new IOException("DBGLINK_GHIDRA_TOKEN length is invalid");
            }
            return value;
        }

        byte[] randomBytes = new byte[32];
        RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Best-effort owner-only restriction, fail-closed when non-default.
     * POSIX first (0600), then a Windows user-only DACL (owner + SYSTEM when
     * resolvable). Returns normally on the default location even if neither
     * view is available (documented residual); throws when the operator
     * pinned a non-default endpoint directory and the token file cannot be
     * locked down. Callers delete the published file on failure.
     */
    private static void applyOwnerOnlyPermissionsOrFailClosed(Path endpointPath) throws IOException {
        try {
            if (tryApplyOwnerOnlyPermissions(endpointPath)) {
                return;
            }
        }
        catch (IOException | RuntimeException ignored) {
            // Fall through to the fail-closed check below.
        }
        if (isNonDefaultEndpointConfig()) {
            throw new IOException("Ghidra endpoint permissions could not be restricted to the current user");
        }
    }

    private static boolean tryApplyOwnerOnlyPermissions(Path endpointPath) throws IOException {
        PosixFileAttributeView posix =
            Files.getFileAttributeView(endpointPath, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            try {
                Files.setPosixFilePermissions(
                    endpointPath,
                    EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
                return true;
            }
            catch (UnsupportedOperationException ignored) {
                // Fall through to the Windows ACL path.
            }
        }

        AclFileAttributeView aclView =
            Files.getFileAttributeView(endpointPath, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (aclView == null) {
            return false;
        }
        UserPrincipal owner = Files.getOwner(endpointPath, LinkOption.NOFOLLOW_LINKS);
        // The launcher owns the endpoint directory and must be able to remove
        // the whole run tree on shutdown, so the owner entry carries DELETE.
        // This widens nothing: the owner implicitly holds WRITE_DAC and can
        // already re-grant itself DELETE (verified against icacls), while
        // readers stay limited to owner + SYSTEM.
        Set<AclEntryPermission> filePermissions = EnumSet.of(
            AclEntryPermission.READ_DATA,
            AclEntryPermission.WRITE_DATA,
            AclEntryPermission.APPEND_DATA,
            AclEntryPermission.READ_NAMED_ATTRS,
            AclEntryPermission.WRITE_NAMED_ATTRS,
            AclEntryPermission.READ_ATTRIBUTES,
            AclEntryPermission.WRITE_ATTRIBUTES,
            AclEntryPermission.DELETE,
            AclEntryPermission.READ_ACL,
            AclEntryPermission.SYNCHRONIZE);
        List<AclEntry> restricted = new ArrayList<>(2);
        restricted.add(AclEntry.newBuilder()
            .setType(AclEntryType.ALLOW)
            .setPrincipal(owner)
            .setPermissions(filePermissions)
            .build());
        try {
            UserPrincipalLookupService lookup =
                endpointPath.getFileSystem().getUserPrincipalLookupService();
            UserPrincipal system = null;
            try {
                system = lookup.lookupPrincipalByName("NT AUTHORITY\\SYSTEM");
            }
            catch (RuntimeException | IOException ignored) {
                try {
                    system = lookup.lookupPrincipalByName("SYSTEM");
                }
                catch (RuntimeException | IOException ignored2) {
                    system = null;
                }
            }
            if (system != null && !system.getName().equals(owner.getName())) {
                restricted.add(AclEntry.newBuilder()
                    .setType(AclEntryType.ALLOW)
                    .setPrincipal(system)
                    .setPermissions(filePermissions)
                    .build());
            }
        }
        catch (RuntimeException ignored) {
            // SYSTEM is a convenience grant; the owner entry is the requirement.
        }
        aclView.setAcl(restricted);
        return true;
    }

    private static boolean isNonDefaultEndpointConfig() {
        String endpoint = System.getenv("DBGLINK_GHIDRA_ENDPOINT");
        if (endpoint != null && !endpoint.isBlank()) {
            return true;
        }
        String directory = System.getenv("DBGLINK_GHIDRA_ENDPOINT_DIR");
        return directory != null && !directory.isBlank();
    }

    static boolean constantTimeEquals(byte[] expectedUtf8, String actual) {
        if (expectedUtf8 == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
            expectedUtf8,
            actual.getBytes(StandardCharsets.UTF_8)
        );
    }

}
