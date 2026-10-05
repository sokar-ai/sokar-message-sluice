package org.fuin.sokar.msgsluice.filter.detect;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.fuin.sokar.msgsluice.filter.decision.Severity;
import org.fuin.sokar.msgsluice.filter.decision.Stage;

/**
 * A run no English word could be: characters without whitespace or a separator, longer than
 * {@code maxTokenLength}. Every block of base64, hex or base32 worth sending is one. Issue 005's proof of
 * concept, kept as one rule among several of doc/detectors.md.
 *
 * <p>
 * Measured between separators and on the {@link Masked} text: paths, file names and Markdown links are long
 * without being encoded, and in this repository's own documentation they refused one paragraph in twenty when
 * the whole token was measured.
 */
public final class LongTokenDetector implements ContentDetector {

    public static final String RULE_ID = "ENCODING/LONG_TOKEN";

    public static final String CATEGORY = "ENCODED_DATA";

    /** The longest common English word is about 30 characters. */
    public static final int DEFAULT_MAX_TOKEN_LENGTH = 35;

    /**
     * What joins words in a path, a file name, an identifier or a query: a run is measured between them. Base64
     * and base64url can still be cut short by one of these; the encoding signatures name those.
     */
    private static final String SEPARATORS = "/._-()[]:?&=#,;|$@+~*<>{}'\"`!";

    private final int maxTokenLength;

    public LongTokenDetector(final int maxTokenLength) {
        if (maxTokenLength < 1) {
            throw new IllegalArgumentException("maxTokenLength must be positive: " + maxTokenLength);
        }
        this.maxTokenLength = maxTokenLength;
    }

    @Override
    public String id() {
        return "builtin/long-token@1";
    }

    @Override
    public Set<String> ruleIds() {
        return Set.of(RULE_ID);
    }

    @Override
    public Set<String> categories() {
        return Set.of(CATEGORY);
    }

    @Override
    public List<DetectorFinding> inspect(final TextUnderCheck under) {
        final Masked masked = Masked.of(under.text());
        final String text = masked.text();
        final List<DetectorFinding> findings = new ArrayList<>();
        for (final int[] token : Tokens.of(text)) {
            int start = token[0];
            for (int i = token[0]; i <= token[1]; i++) {
                if (i == token[1] || SEPARATORS.indexOf(text.charAt(i)) >= 0) {
                    if (i - start > maxTokenLength) {
                        final int[] span = masked.toSource(start, i);
                        findings.add(new DetectorFinding(RULE_ID, Stage.TEXT, Severity.BLOCKING, CATEGORY, span[0],
                                span[1], "A run of " + (i - start) + " characters without whitespace or a "
                                        + "separator. No English word is longer than " + maxTokenLength
                                        + " characters, and encoded data looks exactly like this."));
                    }
                    start = i + 1;
                }
            }
        }
        return findings;
    }

}
