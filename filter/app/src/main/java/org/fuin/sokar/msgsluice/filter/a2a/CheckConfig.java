package org.fuin.sokar.msgsluice.filter.a2a;

import java.util.Objects;
import java.util.Set;

import org.fuin.sokar.msgsluice.filter.decision.Severity;

/**
 * The limits of the envelope check.
 *
 * @param allowedRoles         the roles the outer message may carry; empty means any. By default an agent's
 *                             and a person's: a person writes into a conversation as {@code ROLE_USER}, and
 *                             only the host knows whether a container wrote a file, so refusing a container's
 *                             {@code ROLE_USER} is the host's check and not this filter's
 * @param urlPartSeverity      what a {@code url} part is; {@code BLOCKING} unless configured down
 * @param maxParts             parts per message
 * @param maxTextLengthPerPart characters per text part
 * @param maxFileSizeBytes     bytes per file, checked before it is parsed
 * @param maxIdLength          characters per id and per peer name
 * @param maxMetadataDepth     nesting depth of a metadata object
 * @param maxMetadataChars     characters of keys and values in one metadata object, all levels together
 * @param maxReferenceTaskIds  entries in one message's {@code referenceTaskIds}
 */
public record CheckConfig(Set<String> allowedRoles, Severity urlPartSeverity, int maxParts, int maxTextLengthPerPart,
        long maxFileSizeBytes, int maxIdLength, int maxMetadataDepth, int maxMetadataChars,
        int maxReferenceTaskIds) {

    public CheckConfig {
        allowedRoles = Set.copyOf(allowedRoles);
        Objects.requireNonNull(urlPartSeverity, "urlPartSeverity");
        if (urlPartSeverity == Severity.INFO) {
            throw new IllegalArgumentException("A url part is at least SUSPICIOUS");
        }
        positive("maxParts", maxParts);
        positive("maxTextLengthPerPart", maxTextLengthPerPart);
        positive("maxFileSizeBytes", maxFileSizeBytes);
        positive("maxIdLength", maxIdLength);
        positive("maxMetadataDepth", maxMetadataDepth);
        positive("maxMetadataChars", maxMetadataChars);
        positive("maxReferenceTaskIds", maxReferenceTaskIds);
    }

    /** Far above real need, and a cap against bloat. */
    public static CheckConfig defaults() {
        return new CheckConfig(Set.of("ROLE_AGENT", "ROLE_USER"), Severity.BLOCKING, 32, 64 * 1024, 1024 * 1024, 128, 8, 16 * 1024,
                32);
    }

    private static void positive(final String name, final long value) {
        if (value < 1) {
            throw new IllegalArgumentException(name + " must be positive: " + value);
        }
    }

}
