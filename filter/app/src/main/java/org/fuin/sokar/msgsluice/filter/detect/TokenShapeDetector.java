package org.fuin.sokar.msgsluice.filter.detect;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.fuin.sokar.msgsluice.filter.decision.Severity;
import org.fuin.sokar.msgsluice.filter.decision.Stage;

/**
 * Tokens shaped like no English word: mostly digits and capitals, almost no vowels, or full of the symbols
 * encodings use. Each is weak alone and {@code SUSPICIOUS}; two different ones in a message reject under the
 * default policy. Runs on the {@link Masked} text, so numbers, dates, UUIDs and acronyms do not count.
 */
public final class TokenShapeDetector implements ContentDetector {

    public static final String DIGIT_UPPER = "ENCODING/DIGIT_UPPER_TOKEN";

    public static final String VOWELLESS = "ENCODING/VOWELLESS_TOKEN";

    public static final String SYMBOL_HEAVY = "ENCODING/SYMBOL_HEAVY_TOKEN";

    public static final String PUNCTUATION_HEAVY = "ENCODING/PUNCTUATION_HEAVY_TOKEN";

    public static final String CATEGORY = "ENCODED_DATA";

    /** The symbols of base64, base64url and URL-encoding. */
    private static final String ENCODING_SYMBOLS = "+/=%_-";

    /** What English and code in prose use around words; everything else counts as punctuation here. */
    private static final String ORDINARY = ".,;:!?'\"()-_/";

    private final double maxDigitUpperShare;

    private final double minVowelShare;

    private final double maxSymbolShare;

    public TokenShapeDetector(final double maxDigitUpperShare, final double minVowelShare,
            final double maxSymbolShare) {
        this.maxDigitUpperShare = maxDigitUpperShare;
        this.minVowelShare = minVowelShare;
        this.maxSymbolShare = maxSymbolShare;
    }

    @Override
    public String id() {
        return "builtin/token-shape@1";
    }

    @Override
    public Set<String> ruleIds() {
        return Set.of(DIGIT_UPPER, VOWELLESS, SYMBOL_HEAVY, PUNCTUATION_HEAVY);
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
            final int length = token[1] - token[0];
            if (length <= 8) {
                continue;
            }
            int digitsUpper = 0;
            int letters = 0;
            int vowels = 0;
            int symbols = 0;
            int punctuation = 0;
            for (int i = token[0]; i < token[1]; i++) {
                final char c = text.charAt(i);
                if (Character.isDigit(c) || Character.isUpperCase(c)) {
                    digitsUpper++;
                }
                if (Character.isLetter(c)) {
                    letters++;
                    if (Tokens.isVowel(c)) {
                        vowels++;
                    }
                }
                if (ENCODING_SYMBOLS.indexOf(c) >= 0) {
                    symbols++;
                }
                if (!Character.isLetterOrDigit(c) && ORDINARY.indexOf(c) < 0) {
                    punctuation++;
                }
            }
            final int[] span = masked.toSource(token[0], token[1]);
            final int digits = countDigits(text, token[0], token[1]);
            final boolean wordLike = letters > 0 && (double) vowels / letters >= 0.25;
            // Capitals with vowels and no digits are a word in capitals, ENCODING/LONG_TOKEN for instance.
            if ((double) digitsUpper / length > maxDigitUpperShare && (digits >= 2 || !wordLike)) {
                findings.add(finding(DIGIT_UPPER, span, "A word of " + length + " characters that is mostly digits "
                        + "and capitals (" + percent(digitsUpper, length) + "), as encoded data is."));
            }
            if (length > 12 && letters >= 8 && (double) vowels / letters < minVowelShare) {
                findings.add(finding(VOWELLESS, span, "A word of " + length + " characters with almost no vowels ("
                        + percent(vowels, letters) + " of its letters). No English word is spelled like that."));
            }
            // A payload is mostly letters and digits; a markdown rule like |---|---| is not a payload.
            final boolean mostlyAlphanumeric = (double) (letters + digits) / length >= 0.4;
            final int kinds = distinctSymbols(text, token[0], token[1]);
            if (length > 12 && mostlyAlphanumeric && kinds >= 2 && (double) symbols / length > maxSymbolShare) {
                findings.add(finding(SYMBOL_HEAVY, span, "A word of " + length + " characters in which "
                        + percent(symbols, length) + " are the symbols of base64 or URL-encoding."));
            }
            if (length > 12 && mostlyAlphanumeric && kinds >= 3 && (double) punctuation / length > maxSymbolShare) {
                findings.add(finding(PUNCTUATION_HEAVY, span, "A word of " + length + " characters in which "
                        + percent(punctuation, length) + " are punctuation, as in uuencode or base85."));
            }
        }
        return findings;
    }

    private static DetectorFinding finding(final String rule, final int[] span, final String reason) {
        return new DetectorFinding(rule, Stage.TEXT, Severity.SUSPICIOUS, CATEGORY, span[0], span[1], reason);
    }

    private static int countDigits(final String text, final int start, final int end) {
        int digits = 0;
        for (int i = start; i < end; i++) {
            if (Character.isDigit(text.charAt(i))) {
                digits++;
            }
        }
        return digits;
    }

    private static int distinctSymbols(final String text, final int start, final int end) {
        return (int) text.substring(start, end).chars().filter(c -> !Character.isLetterOrDigit(c)).distinct()
                .count();
    }

    static String percent(final int part, final int whole) {
        return Math.round(100.0 * part / whole) + " %";
    }

}
