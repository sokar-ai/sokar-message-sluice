package org.fuin.sokar.msgsluice.filter.detect;

import java.text.Normalizer.Form;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.fuin.sokar.msgsluice.filter.decision.Severity;
import org.fuin.sokar.msgsluice.filter.decision.Stage;

/**
 * The frame's normalization, done once per text so every detector sees the same thing: Unicode NFKC, line
 * endings as {@code \n}, invisible characters removed, and look-alike letters from other scripts folded to Latin
 * inside a token that mixes scripts. Every character of the result remembers where it came from, so a finding
 * made on the normalized text points into the original.
 *
 * <p>
 * What it removes is itself reported: an invisible character is where steganography hides, and a word spelled
 * with a Cyrillic {@code а} is a word somebody wanted a filter not to read.
 */
public final class Normalizer {

    public static final String ID = "builtin/normalize@1";

    public static final String INVISIBLE = "UNICODE/INVISIBLE_CHARACTER";

    public static final String MIXED_SCRIPT = "UNICODE/MIXED_SCRIPT";

    public static final String CATEGORY = "OBFUSCATION";

    public static final Set<String> RULE_IDS = Set.of(INVISIBLE, MIXED_SCRIPT);

    /** From this many invisible characters in one text on, they are a channel, not an accident. */
    static final int INVISIBLE_BLOCKING_FROM = 8;

    /** Cyrillic and Greek letters that look like Latin ones. */
    private static final Map<Integer, Character> CONFUSABLES = confusables();

    private Normalizer() {
    }

    /**
     * The normalized text and where each of its characters came from.
     *
     * @param original the text as it was in the message
     * @param text     the normalized text
     * @param from     for each character of {@code text}, the offset in {@code original} where it starts
     * @param to       for each character of {@code text}, the offset in {@code original} after its source
     * @param findings what normalization itself found, with offsets into {@code original}
     */
    public record Normalized(String original, String text, int[] from, int[] to, List<DetectorFinding> findings) {

        /** The span in the original that the normalized span {@code [start, end)} came from. */
        public int[] toOriginal(final int start, final int end) {
            if (start < 0 || end > text.length() || start >= end) {
                return new int[] {-1, -1};
            }
            return new int[] {from[start], to[end - 1]};
        }

    }

    public static Normalized normalize(final String original) {
        final StringBuilder out = new StringBuilder(original.length());
        final List<Integer> from = new ArrayList<>(original.length());
        final List<Integer> to = new ArrayList<>(original.length());
        final List<int[]> invisible = new ArrayList<>();
        // Emoji presentation is exempt only while each symbol always or never carries it: a choice made per
        // symbol, with and without, is one hidden bit each time.
        final Map<Integer, List<int[]>> emojiSelectors = new java.util.HashMap<>();
        final Set<Integer> bareSymbols = new java.util.HashSet<>();

        int i = 0;
        while (i < original.length()) {
            final int cp = original.codePointAt(i);
            final int next = i + Character.charCount(cp);
            if (cp == '\r') {
                // \r\n and a lone \r both become one \n.
                final int end = next < original.length() && original.charAt(next) == '\n' ? next + 1 : next;
                append(out, from, to, "\n", i, end);
                i = end;
                continue;
            }
            if (Character.getType(cp) == Character.OTHER_SYMBOL
                    && (next >= original.length() || original.codePointAt(next) != 0xFE0F)) {
                bareSymbols.add(cp);
            }
            final String normalized = java.text.Normalizer.normalize(Character.toString(cp), Form.NFKC);
            // Tested after NFKC too: a character that is visible only until it is normalized is invisible.
            if (isInvisible(cp) || normalized.codePoints().anyMatch(Normalizer::isInvisible)) {
                if (cp == 0xFE0F && isEmojiJoiner(original, i, cp, next)) {
                    emojiSelectors.computeIfAbsent(original.codePointBefore(i), k -> new ArrayList<>())
                            .add(new int[] {i, next});
                } else if (!isEmojiJoiner(original, i, cp, next)) {
                    invisible.add(new int[] {i, next});
                }
                i = next;
                continue;
            }
            append(out, from, to, normalized, i, next);
            i = next;
        }
        for (final Map.Entry<Integer, List<int[]>> e : emojiSelectors.entrySet()) {
            if (bareSymbols.contains(e.getKey())) {
                invisible.addAll(e.getValue());
            }
        }
        invisible.sort(java.util.Comparator.comparingInt(run -> run[0]));
        final int invisibleCount = invisible.size();
        final List<int[]> invisibleRuns = new ArrayList<>();
        for (final int[] one : invisible) {
            if (!invisibleRuns.isEmpty() && invisibleRuns.get(invisibleRuns.size() - 1)[1] == one[0]) {
                invisibleRuns.get(invisibleRuns.size() - 1)[1] = one[1];
            } else {
                invisibleRuns.add(new int[] {one[0], one[1]});
            }
        }

        final List<DetectorFinding> findings = new ArrayList<>();
        final Severity invisibleSeverity = invisibleCount >= INVISIBLE_BLOCKING_FROM ? Severity.BLOCKING
                : Severity.SUSPICIOUS;
        for (final int[] run : invisibleRuns) {
            findings.add(new DetectorFinding(INVISIBLE, Stage.TEXT, invisibleSeverity, CATEGORY, run[0], run[1],
                    "Invisible characters (" + (run[1] - run[0]) + " of " + invisibleCount + " in this text). "
                            + "They carry nothing a reader sees, which makes them a hiding place."));
        }
        final int[] fromArray = from.stream().mapToInt(Integer::intValue).toArray();
        final int[] toArray = to.stream().mapToInt(Integer::intValue).toArray();
        final String folded = foldMixedScripts(out, fromArray, toArray, findings);
        return new Normalized(original, folded, fromArray, toArray, List.copyOf(findings));
    }

    private static void append(final StringBuilder out, final List<Integer> from, final List<Integer> to,
            final String chars, final int start, final int end) {
        out.append(chars);
        for (int k = 0; k < chars.length(); k++) {
            from.add(start);
            to.add(end);
        }
    }

    /** Format characters (zero-width, bidi controls, tags, soft hyphen) and variation selectors. */
    static boolean isInvisible(final int cp) {
        return Character.getType(cp) == Character.FORMAT || cp >= 0xFE00 && cp <= 0xFE0F
                || cp >= 0xE0100 && cp <= 0xE01EF || cp == 0x034F || cp == 0x115F || cp == 0x1160 || cp == 0x3164;
    }

    /**
     * The joiner inside an emoji sequence and the emoji-presentation selector after a symbol are how ordinary chat
     * writes emoji. They are removed like any other invisible character, but not reported. The text-presentation
     * selector is not exempt: beside the emoji one it would make every symbol carry a bit.
     */
    private static boolean isEmojiJoiner(final String text, final int at, final int cp, final int next) {
        final boolean afterSymbol = at > 0 && Character.getType(text.codePointBefore(at)) == Character.OTHER_SYMBOL;
        if (cp == 0xFE0F) {
            return afterSymbol;
        }
        if (cp == 0x200D) {
            return afterSymbol && next < text.length()
                    && Character.getType(text.codePointAt(next)) == Character.OTHER_SYMBOL;
        }
        return false;
    }

    /** Inside a token that mixes Latin with Cyrillic or Greek, look-alikes become the Latin letter they imitate. */
    private static String foldMixedScripts(final StringBuilder text, final int[] from, final int[] to,
            final List<DetectorFinding> findings) {
        int i = 0;
        while (i < text.length()) {
            while (i < text.length() && Character.isWhitespace(text.charAt(i))) {
                i++;
            }
            final int start = i;
            boolean latin = false;
            boolean other = false;
            while (i < text.length() && !Character.isWhitespace(text.charAt(i))) {
                final Character.UnicodeScript script = Character.UnicodeScript.of(text.charAt(i));
                latin |= script == Character.UnicodeScript.LATIN;
                other |= script == Character.UnicodeScript.CYRILLIC || script == Character.UnicodeScript.GREEK;
                i++;
            }
            if (latin && other) {
                for (int k = start; k < i; k++) {
                    final Character latinLetter = CONFUSABLES.get((int) text.charAt(k));
                    if (latinLetter != null) {
                        text.setCharAt(k, latinLetter);
                    }
                }
                findings.add(new DetectorFinding(MIXED_SCRIPT, Stage.TEXT, Severity.SUSPICIOUS, CATEGORY,
                        from[start], to[i - 1], "A word mixes Latin letters with Cyrillic or Greek look-alikes, "
                                + "which is how a word is spelled so that a filter does not recognize it."));
            }
        }
        return text.toString();
    }

    private static Map<Integer, Character> confusables() {
        final String pairs = "аaеeоoрpсcхxуyіiјjѕsԁdһhӏlАAВBЕEКKМMНHОOРPСCТTХXІIЈJЅS"
                + "αaοoρpνvιiκkΑAΒBΕEΖZΗHΙIΚKΜMΝNΟOΡPΤTΥYΧX";
        final java.util.HashMap<Integer, Character> map = new java.util.HashMap<>();
        for (int k = 0; k < pairs.length(); k += 2) {
            map.put((int) pairs.charAt(k), pairs.charAt(k + 1));
        }
        return Map.copyOf(map);
    }

}
