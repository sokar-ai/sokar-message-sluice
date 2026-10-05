package org.fuin.sokar.msgsluice.filter.detect;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.fuin.sokar.msgsluice.filter.decision.Severity;
import org.fuin.sokar.msgsluice.filter.decision.Stage;

/**
 * Whether a whole text is distributed like English: its letters against English letter frequencies, and its
 * share of whitespace. Only meaningful above a minimum length. Runs on the {@link Masked} text.
 *
 * <p>
 * The letter test uses chi-squared <em>per letter</em> rather than a significance level. At a fixed
 * significance a long English text fails simply for being long, because real prose never matches a reference
 * table exactly; divided by the number of letters, the statistic measures how far the distribution is from
 * English, whatever the length.
 */
public final class DistributionDetector implements ContentDetector {

    public static final String LETTERS = "ENCODING/LETTER_DISTRIBUTION";

    public static final String WHITESPACE = "ENCODING/WHITESPACE_SHARE";

    public static final String CATEGORY = "ENCODED_DATA";

    /** Relative frequencies of a to z in English text. */
    private static final double[] ENGLISH = {0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609,
            0.0697, 0.0015, 0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193, 0.0010, 0.0599, 0.0633, 0.0906, 0.0276,
            0.0098, 0.0236, 0.0015, 0.0197, 0.0007};

    private final int minLength;

    private final double maxChiSquarePerLetter;

    private final double minWhitespaceShare;

    public DistributionDetector(final int minLength, final double maxChiSquarePerLetter,
            final double minWhitespaceShare) {
        this.minLength = minLength;
        this.maxChiSquarePerLetter = maxChiSquarePerLetter;
        this.minWhitespaceShare = minWhitespaceShare;
    }

    @Override
    public String id() {
        return "builtin/english-distribution@1";
    }

    @Override
    public Set<String> ruleIds() {
        return Set.of(LETTERS, WHITESPACE);
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
        if (text.strip().length() < minLength) {
            return findings;
        }
        final int[] span = masked.toSource(0, text.length());
        final double chi = chiSquarePerLetter(text);
        if (chi > maxChiSquarePerLetter) {
            // Without a letter from a to z there is nothing to count, and "Infinity per letter" names no measurement.
            findings.add(new DetectorFinding(LETTERS, Stage.TEXT, Severity.SUSPICIOUS, CATEGORY, span[0], span[1],
                    Double.isInfinite(chi) ? "The text has no letters from a to z, so it is not English prose."
                            : String.format(Locale.ROOT, "The letters are distributed unlike English (%.2f per "
                                    + "letter against at most %.2f).", chi, maxChiSquarePerLetter)));
        }
        final double whitespace = whitespaceShare(text);
        if (whitespace < minWhitespaceShare) {
            findings.add(new DetectorFinding(WHITESPACE, Stage.TEXT, Severity.SUSPICIOUS, CATEGORY, span[0], span[1],
                    String.format(Locale.ROOT, "Only %.0f %% of the text is whitespace; English has about one space "
                            + "in six characters.", 100 * whitespace)));
        }
        return findings;
    }

    public static double chiSquarePerLetter(final String text) {
        final int[] counts = new int[26];
        int n = 0;
        for (int i = 0; i < text.length(); i++) {
            final char c = Character.toLowerCase(text.charAt(i));
            if (c >= 'a' && c <= 'z') {
                counts[c - 'a']++;
                n++;
            }
        }
        if (n == 0) {
            return Double.POSITIVE_INFINITY;
        }
        double chi = 0.0;
        for (int k = 0; k < 26; k++) {
            final double expected = ENGLISH[k] * n;
            chi += (counts[k] - expected) * (counts[k] - expected) / expected;
        }
        return chi / n;
    }

    public static double whitespaceShare(final String text) {
        int spaces = 0;
        for (int i = 0; i < text.length(); i++) {
            if (Character.isWhitespace(text.charAt(i))) {
                spaces++;
            }
        }
        return (double) spaces / text.length();
    }

}
