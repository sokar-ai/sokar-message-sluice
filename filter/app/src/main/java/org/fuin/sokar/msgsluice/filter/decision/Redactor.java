package org.fuin.sokar.msgsluice.filter.decision;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Masks what a rule matched before it goes anywhere. A refusal must never exfiltrate what it prevents, so
 * every excerpt in an answer, a receipt or a log line comes out of here.
 */
public final class Redactor {

    public enum Mode {
        /** The first four characters of a long match, then stars. Nothing of a short one. */
        PARTIAL,
        /** Only the category. */
        FULL,
        /** A SHA-256 prefix, so that repeats stay correlatable without being readable. */
        HASH
    }

    /** Below this length even four characters are too much of the secret. */
    private static final int SHOW_PREFIX_FROM = 16;

    private static final int PREFIX = 4;

    /** Short enough that a redacted excerpt is never itself a long token. */
    private static final int MAX_STARS = 12;

    private final Mode mode;

    public Redactor(final Mode mode) {
        this.mode = Objects.requireNonNull(mode, "mode");
    }

    public Mode mode() {
        return mode;
    }

    /**
     * @throws IllegalArgumentException when the offsets do not describe a non-empty range of {@code text}; such a
     *                                  finding cannot be redacted and must refuse the message instead
     */
    public String redact(final String text, final int start, final int end, final String category) {
        if (start < 0 || end > text.length() || start >= end) {
            throw new IllegalArgumentException(
                    "Offsets " + start + "-" + end + " do not fit a text of length " + text.length());
        }
        final String matched = text.substring(start, end);
        return switch (mode) {
            case FULL -> "[REDACTED:" + category + "]";
            case HASH -> "sha256:" + sha256(matched).substring(0, 12);
            case PARTIAL -> partial(matched);
        };
    }

    private static String partial(final String matched) {
        final StringBuilder sb = new StringBuilder();
        int shown = 0;
        if (matched.length() >= SHOW_PREFIX_FROM) {
            // Only plain letters and digits, so an excerpt cannot carry a control character or markup.
            matched.substring(0, PREFIX).chars()
                    .forEach(c -> sb.append(Character.isLetterOrDigit(c) && c < 128 ? (char) c : '?'));
            shown = PREFIX;
        }
        sb.append("*".repeat(Math.min(matched.length() - shown, MAX_STARS)));
        return sb.toString();
    }

    static String sha256(final String value) {
        return sha256(value.getBytes(StandardCharsets.UTF_8));
    }

    public static String sha256(final byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (final NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Every Java runtime has SHA-256", ex);
        }
    }

}
