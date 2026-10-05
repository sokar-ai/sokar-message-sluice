package org.fuin.sokar.msgsluice.filter.detect;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.fuin.sokar.msgsluice.filter.decision.Severity;
import org.fuin.sokar.msgsluice.filter.decision.Stage;

/**
 * Shannon entropy over sliding windows of the {@link Masked} text, <strong>folded</strong>: letters to lower
 * case, every whitespace to one space, every other non-alphanumeric character to one symbol; digits stay
 * themselves. Overlapping windows mean a payload cannot fall between two of them, and adjacent windows above the
 * threshold are reported as one finding naming the highest value.
 *
 * <p>
 * Folded, because raw entropy does not separate the prose agents write from encoded data: raw 128-character
 * windows of this repository's own documentation reach 5.14 bits, as high as base64. Capitals and punctuation
 * make technical prose look random, and folding takes that away. Digits are not folded, or base36 would look
 * like English. Measured over 2916 paragraphs of agent prose, 64-character windows: English at
 * p99.9 4.42 and at most 4.56; 80 characters of base64 or base36 in a sentence at a median of 4.75 and 4.80.
 */
public final class EntropyDetector implements ContentDetector {

    public static final String RULE_ID = "ENCODING/WINDOW_ENTROPY";

    public static final String CATEGORY = "ENCODED_DATA";

    private final double threshold;

    private final int windowSize;

    private final int step;

    private final int minLength;

    /**
     * @param minLength a text shorter than this is not measured at all; one shorter than a window but at least
     *                  this long is measured as a single window
     */
    public EntropyDetector(final double threshold, final int windowSize, final int step, final int minLength) {
        if (windowSize < 16 || step < 1 || step > windowSize || minLength < 16) {
            throw new IllegalArgumentException("Window " + windowSize + ", step " + step + ", minimum " + minLength);
        }
        this.threshold = threshold;
        this.windowSize = windowSize;
        this.step = step;
        this.minLength = minLength;
    }

    @Override
    public String id() {
        return "builtin/entropy@1";
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
        final String text = fold(masked.text());
        final List<DetectorFinding> findings = new ArrayList<>();
        if (text.length() < minLength) {
            return findings;
        }
        final int size = Math.min(windowSize, text.length());
        int runStart = -1;
        int runEnd = -1;
        double runMax = 0.0;
        for (final int start : windowStarts(text.length(), windowSize, step)) {
            final double h = entropy(text, start, start + size);
            if (h > threshold) {
                if (runStart >= 0 && start <= runEnd) {
                    runEnd = start + size;
                } else {
                    flush(masked, runStart, runEnd, runMax, findings);
                    runStart = start;
                    runEnd = start + size;
                    runMax = 0.0;
                }
                runMax = Math.max(runMax, h);
            }
        }
        flush(masked, runStart, runEnd, runMax, findings);
        return findings;
    }

    /**
     * Where each window over a text of {@code length} starts: every {@code step}, and a last one ending at the
     * text's end, so the tail is never skipped. A text shorter than a window is one window. Calibration walks the
     * same windows, so that it measures exactly what the detector does.
     */
    public static int[] windowStarts(final int length, final int window, final int step) {
        final int size = Math.min(window, length);
        final java.util.List<Integer> starts = new ArrayList<>();
        int start = 0;
        for (; start + size <= length; start += step) {
            starts.add(start);
        }
        if (starts.get(starts.size() - 1) + size < length) {
            starts.add(length - size);
        }
        return starts.stream().mapToInt(Integer::intValue).toArray();
    }

    private void flush(final Masked masked, final int start, final int end, final double max,
            final List<DetectorFinding> findings) {
        if (start < 0) {
            return;
        }
        final int[] span = masked.toSource(start, end);
        findings.add(new DetectorFinding(RULE_ID, Stage.TEXT, Severity.BLOCKING, CATEGORY, span[0], span[1],
                String.format(Locale.ROOT, "%d characters with an entropy of up to %.2f bits per character, case "
                        + "and punctuation aside; English stays below %.2f, and encoded or encrypted data lies above "
                        + "it.", end - start, max, threshold)));
    }

    /** Letters in lower case, one symbol for whitespace, one for everything else that is not a digit. */
    public static String fold(final String text) {
        final char[] out = new char[text.length()];
        for (int i = 0; i < out.length; i++) {
            final char c = text.charAt(i);
            if (Character.isLetter(c)) {
                out[i] = Character.toLowerCase(c);
            } else if (Character.isDigit(c)) {
                out[i] = c;
            } else if (Character.isWhitespace(c)) {
                out[i] = ' ';
            } else {
                out[i] = '.';
            }
        }
        return new String(out);
    }

    /** Shannon entropy of {@code text[start, end)}, in bits per character. */
    public static double entropy(final String text, final int start, final int end) {
        final java.util.Map<Character, Integer> counts = new java.util.HashMap<>();
        for (int i = start; i < end; i++) {
            counts.merge(text.charAt(i), 1, Integer::sum);
        }
        final double n = end - start;
        double h = 0.0;
        for (final int count : counts.values()) {
            final double p = count / n;
            h -= p * Math.log(p) / Math.log(2);
        }
        return h;
    }

}
