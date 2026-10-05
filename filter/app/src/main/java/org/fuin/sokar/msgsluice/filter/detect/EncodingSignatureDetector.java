package org.fuin.sokar.msgsluice.filter.detect;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.fuin.sokar.msgsluice.filter.decision.Severity;
import org.fuin.sokar.msgsluice.filter.decision.Stage;

import org.jspecify.annotations.Nullable;

/**
 * Recognizes an encoding by its alphabet and its shape, and names it - which is what makes a refusal
 * explainable to the agent that has to act on it. Every finding here is {@code BLOCKING}: a named encoding of
 * this length is data, whatever else the text says.
 *
 * <p>
 * Runs on the text with only URLs and isolated UUIDs masked; numbers stay, or a run of 0 and 1 would be a
 * number to it. <strong>A full hash in hex is refused too</strong>: 32 hex characters of a payload and an MD5
 * look the same, and a message that means a commit can name it by its short form.
 */
public final class EncodingSignatureDetector implements ContentDetector {

    public static final String CATEGORY = "ENCODED_DATA";

    public static final String PEM = "ENCODING/PEM";

    public static final String DATA_URI = "ENCODING/DATA_URI";

    public static final String BASE64 = "ENCODING/BASE64";

    public static final String BASE64URL = "ENCODING/BASE64URL";

    public static final String BASE58 = "ENCODING/BASE58";

    public static final String BASE32 = "ENCODING/BASE32";

    public static final String BASE85 = "ENCODING/BASE85";

    public static final String HEX = "ENCODING/HEX";

    public static final String URL_ENCODING = "ENCODING/URL_ENCODING";

    public static final String QUOTED_PRINTABLE = "ENCODING/QUOTED_PRINTABLE";

    public static final String UUENCODE = "ENCODING/UUENCODE";

    public static final String BINARY = "ENCODING/BINARY_STRING";

    private static final Pattern PEM_HEADER = Pattern.compile("-----BEGIN [A-Z0-9 ]{1,40}-----");

    /*
     * Every repeated group here is possessive. Java's matcher recurses once per repetition of a group that can
     * backtrack, so 64 KB of capitals or of "12, 34, " overflowed the stack - and a check that cannot run refuses.
     * Each possessive form was compared with the backtracking one on random inputs and matched the same spans.
     */

    private static final Pattern DATA = Pattern.compile("(?i)data:[\\w/+.-]*+(?:;(?!base64,)[\\w=.-]++)*+;base64,");

    private static final Pattern BASE64_RUN = Pattern.compile("[A-Za-z0-9+/_-]+={0,2}");

    private static final Pattern HEX_BYTES = Pattern
            .compile("(?<![0-9A-Fa-f])(?:(?:0x)?[0-9A-Fa-f]{2}[ :,-]{1,2}(?=(?:0x)?[0-9A-Fa-f]{2}(?![0-9A-Fa-f])))"
                    + "{15,}+(?:0x)?[0-9A-Fa-f]{2}(?![0-9A-Fa-f])");

    private static final Pattern PERCENT = Pattern.compile("%[0-9A-Fa-f]{2}");

    private static final Pattern QP = Pattern.compile("=[0-9A-F]{2}");

    private static final Pattern UU_BEGIN = Pattern.compile("(?m)^begin [0-7]{3,4} \\S");

    /** Uuencode's alphabet is space to backtick: no lower case at all, and much punctuation. A single space
     * is a character of it; two in a row are not. */
    private static final Pattern UU_RUN = Pattern.compile("(?:[\\x21-\\x60]| (?! ))++");

    private static final Pattern BASE85_DELIMITED = Pattern.compile("<~[\\x21-\\x75\\s]{8,}~>");

    private static final Pattern BASE85_RUN = Pattern.compile("[\\x21-\\x75]+");

    private static final Pattern BINARY_RUN = Pattern.compile("(?<![01])(?:[01]{8}[ ,]?){4,}+|(?<![01])[01]{32,}");

    private static final int DENSE_ESCAPES = 6;

    /** How many trimmed pieces on either side of a run are tried back on, at most: 81 joins per run. */
    private static final int WIDEN = 8;

    /** A piece of a base-N run, as a payload cut into pieces leaves it. */
    private static final Pattern FRAGMENT = Pattern.compile("[A-Za-z0-9+/_=-]++");

    /** What may stand between two pieces of one payload: whitespace. */
    private static final Pattern SEPARATOR = Pattern.compile("\\s++");

    /** Whitespace written out as an escape, which reads as whitespace too; replaced by as many spaces. */
    private static final Pattern ESCAPED_WHITESPACE = Pattern.compile("\\\\[nrt]");


    /**
     * Uuencode and base85 draw from 64 and 85 characters, so a run of them repeats little. Version numbers, IP
     * addresses and lists of line numbers are punctuation-heavy too, but repeat their digits and dots.
     */
    private static final double RUN_ENTROPY = 4.1;

    private final int minLength;

    public EncodingSignatureDetector(final int minLength) {
        if (minLength < 16) {
            throw new IllegalArgumentException("minLength must be at least 16: " + minLength);
        }
        this.minLength = minLength;
    }

    @Override
    public String id() {
        return "builtin/encoding-signature@1";
    }

    @Override
    public Set<String> ruleIds() {
        return Set.of(PEM, DATA_URI, BASE64, BASE64URL, BASE58, BASE32, BASE85, HEX, URL_ENCODING,
                QUOTED_PRINTABLE, UUENCODE, BINARY);
    }

    @Override
    public Set<String> categories() {
        return Set.of(CATEGORY);
    }

    @Override
    public List<DetectorFinding> inspect(final TextUnderCheck under) {
        final Masked masked = Masked.of(under.text(), false);
        final String text = masked.text();
        final List<DetectorFinding> out = new ArrayList<>();

        each(PEM_HEADER, text, m -> add(out, masked, PEM, m.start(), m.end(), "a PEM block"));
        each(DATA, text, m -> add(out, masked, DATA_URI, m.start(), Math.min(text.length(), m.end() + 16),
                "a data URI with inline base64"));
        each(HEX_BYTES, text, m -> add(out, masked, HEX, m.start(), m.end(), "hex bytes"));
        each(BINARY_RUN, text, m -> add(out, masked, BINARY, m.start(), m.end(), "a binary string"));
        each(UU_BEGIN, text, m -> add(out, masked, UUENCODE, m.start(), m.end(), "a uuencoded file"));
        each(BASE85_DELIMITED, text, m -> add(out, masked, BASE85, m.start(), m.end(), "ascii85"));
        dense(PERCENT, text, masked, URL_ENCODING, "URL-encoded bytes", out);
        dense(QP, text, masked, QUOTED_PRINTABLE, "quoted-printable bytes", out);

        each(BASE64_RUN, text, m -> {
            final String run = m.group();
            final String name = alphabetRun(run);
            if (name != null && run.length() >= minLength) {
                add(out, masked, name, m.start(), m.end(), describe(name));
            }
        });
        splitRuns(text, masked, out);
        each(UU_RUN, text, m -> {
            final String run = m.group().strip();
            // Words in capitals come in runs of letters; uuencode's capitals are scattered between its digits
            // and punctuation, one or two at a time.
            if (run.length() >= minLength && punctuationShare(run) >= 0.2 && distinctPunctuation(run) >= 4
                    && spaceShare(run) < 0.1 && meanLetterRun(run) < 3.2 && letterShare(run) >= 0.2
                    && EntropyDetector.entropy(run, 0, run.length()) >= RUN_ENTROPY) {
                add(out, masked, UUENCODE, m.start(), m.end(), "uuencoded bytes");
            }
        });
        each(BASE85_RUN, text, m -> {
            final String run = m.group();
            if (run.length() >= minLength && punctuationShare(run) >= 0.1 && distinctPunctuation(run) >= 3
                    && hasBothCases(run) && meanLowerRun(run) < 2.6
                    && EntropyDetector.entropy(run, 0, run.length()) >= RUN_ENTROPY) {
                add(out, masked, BASE85, m.start(), m.end(), "base85 bytes");
            }
        });
        return out;
    }

    /**
     * A payload cut into pieces by whitespace - spaces, line breaks, tabs, or those escapes written out - is still
     * the payload: the pieces of a run are joined and judged like one contiguous run. Words and bare punctuation
     * at either end of a run are the sentence around it and are left out; a run whose pieces are more than two
     * thirds words or numbers is prose and never judged. Measured on 13342 paragraphs agents wrote to each other: at
     * most three short commit hashes stood in a row, under 32 characters, so a row of them needs no exception.
     */
    private void splitRuns(final String masked0, final Masked masked, final List<DetectorFinding> out) {
        // Two characters for two: every offset stays the masked text's.
        final String text = ESCAPED_WHITESPACE.matcher(masked0).replaceAll("  ");
        final List<int[]> pieces = new ArrayList<>();
        final Matcher m = FRAGMENT.matcher(text);
        while (m.find()) {
            pieces.add(new int[] {m.start(), m.end()});
        }
        int from = 0;
        for (int i = 1; i <= pieces.size(); i++) {
            if (i == pieces.size()
                    || !SEPARATOR.matcher(text.substring(pieces.get(i - 1)[1], pieces.get(i)[0])).matches()) {
                splitRun(text, pieces.subList(from, i), masked, out);
                from = i;
            }
        }
    }

    private void splitRun(final String text, final List<int[]> pieces, final Masked masked,
            final List<DetectorFinding> out) {
        int first = 0;
        int last = pieces.size() - 1;
        while (first <= last && aroundAPayload(text, pieces.get(first))) {
            first++;
        }
        while (last >= first && aroundAPayload(text, pieces.get(last))) {
            last--;
        }
        if (first > last) {
            return;
        }
        // A piece of the payload can look like a word too, and was then trimmed with the sentence: so up to
        // eight pieces on either side are tried back on - pieces as long as the run's own, since a payload is cut
        // into groups of one length and the words around it rarely are.
        final int group = pieces.get(first)[1] - pieces.get(first)[0];
        for (int left = first; left >= Math.max(0, first - WIDEN); left--) {
            if (left < first && length(pieces.get(left)) != group) {
                break;
            }
            for (int right = last; right <= Math.min(pieces.size() - 1, last + WIDEN); right++) {
                if (right > last && length(pieces.get(right)) != group) {
                    break;
                }
                final String name = judge(text, pieces.subList(left, right + 1));
                if (name != null) {
                    add(out, masked, name, pieces.get(left)[0], pieces.get(right)[1],
                            describe(name) + " cut into pieces");
                    return;
                }
            }
        }
    }

    /** The encoding the joined pieces are, or {@code null} for prose, a single piece, or too few characters. */
    private @Nullable String judge(final String text, final List<int[]> run) {
        if (run.size() < 2) {
            return null;
        }
        final StringBuilder joined = new StringBuilder();
        int prose = 0;
        for (final int[] piece : run) {
            final String s = text.substring(piece[0], piece[1]);
            if (isProse(s)) {
                prose++;
            }
            joined.append(s);
        }
        // Prose is words nearly throughout; a payload's pieces look like words now and then, so only a run of
        // more than two thirds words is left alone.
        if (joined.length() < minLength || prose * 3 > run.size() * 2) {
            return null;
        }
        return alphabetRun(joined.toString());
    }

    private static int length(final int[] piece) {
        return piece[1] - piece[0];
    }

    private static boolean bare(final String text, final int[] piece) {
        return text.substring(piece[0], piece[1]).chars().noneMatch(Character::isLetterOrDigit);
    }

    /** The words of one and two letters prose is made of; any other piece that short is a fragment. */
    private static final Set<String> SHORT_WORDS = Set.of("a", "i", "am", "an", "as", "at", "be", "by", "do", "go",
            "he", "if", "in", "is", "it", "me", "my", "no", "of", "oh", "ok", "on", "or", "so", "to", "up", "us", "we");

    /** Lower case, capitalized, or capitals up to six: a word in capitals longer than that is rarely prose. */
    private static final Pattern WORD_SHAPE = Pattern.compile("[a-z]++|[A-Z][a-z]++|[A-Z]{1,6}+");

    /**
     * A word of prose or a plain number. A word has a word's shape - lower case, capitalized or a few capitals - and
     * a vowel; one of one or two letters must be a common word. A payload's pieces rarely are either.
     */
    private static boolean isProse(final String s) {
        if (s.isEmpty()) {
            return false;
        }
        if (s.matches(".*[-_/].*")) {
            return isJoinedWords(s);
        }
        if (s.chars().allMatch(c -> c >= '0' && c <= '9')) {
            return true;
        }
        if (!WORD_SHAPE.matcher(s).matches()) {
            return false;
        }
        if (s.length() <= 2) {
            return SHORT_WORDS.contains(s.toLowerCase(java.util.Locale.ROOT));
        }
        return s.chars().anyMatch(c -> "AEIOUYaeiouy".indexOf(c) >= 0);
    }

    private static final Pattern NAME_SEGMENT = Pattern.compile("(?=[A-Z0-9]*+[AEIOUY])[A-Z0-9]{1,12}+");

    /**
     * Words, numbers and names joined by dashes, underscores or slashes: an identifier, a path, a flag or a
     * fraction - {@code SOKAR_E2E_MODEL}, {@code Q4-What-The-Agent-Is-Doing}, {@code api/storage}, {@code -cp},
     * {@code 1/1}. Measured on 13342 paragraphs agents wrote to each other: these were what tables and command
     * lines put in a row.
     */
    private static boolean isJoinedWords(final String s) {
        boolean any = false;
        for (final String segment : s.split("[-_/]++")) {
            if (segment.isEmpty()) {
                continue;
            }
            any = true;
            if (segment.length() > 12 || !(WORD.matcher(segment).matches()
                    || NAME_SEGMENT.matcher(segment).matches())) {
                return false;
            }
        }
        return any;
    }

    /** A word, a number or bare punctuation: what a sentence puts before or after a payload. */
    private static boolean aroundAPayload(final String text, final int[] piece) {
        final String s = text.substring(piece[0], piece[1]);
        return isProse(s) || bare(text, piece);
    }

    /**
     * Which base-N encoding a run of letters, digits and base64 symbols is, or {@code null} for one that reads
     * like an identifier: words carry vowels, random alphabets carry digits and few vowels.
     */
    static @Nullable String alphabetRun(final String run) {
        final String body = run.replaceAll("=+$", "");
        // Hex with dashes, a chain of UUIDs for instance, is hex.
        final String undashed = body.replace("-", "");
        if (undashed.length() >= 32 && isHex(undashed) && undashed.chars().anyMatch(Character::isDigit)
                && undashed.chars().anyMatch(Character::isLetter)) {
            return HEX;
        }
        int upper = 0;
        int lower = 0;
        int digits = 0;
        int vowels = 0;
        boolean plusSlash = false;
        boolean dashUnderscore = false;
        boolean notBase58 = false;
        boolean notBase32 = false;
        for (int i = 0; i < body.length(); i++) {
            final char c = body.charAt(i);
            if (Character.isUpperCase(c)) {
                upper++;
            } else if (Character.isLowerCase(c)) {
                lower++;
            } else if (Character.isDigit(c)) {
                digits++;
            }
            if (Tokens.isVowel(c)) {
                vowels++;
            }
            plusSlash |= c == '+' || c == '/';
            dashUnderscore |= c == '-' || c == '_';
            notBase58 |= "0OIl+/-_".indexOf(c) >= 0;
            notBase32 |= !(c >= 'A' && c <= 'Z' || c >= '2' && c <= '7');
        }
        final int letters = upper + lower;
        if (isIdentifier(body)) {
            return null;
        }
        if (!notBase32 && digits > 0) {
            return BASE32;
        }
        // An identifier is words: runs of lower case after each capital. Random letters switch case every one or
        // two characters. Measured: 32 characters of base64 average under 2 lower-case letters per run.
        final double lowerRun = meanLowerRun(body);
        final boolean random = upper >= 2 && lower >= 2
                && (digits >= 1 ? lowerRun < 3.5 : lowerRun < 2.6 && (double) vowels / letters < 0.3);
        if (!random) {
            return null;
        }
        if (plusSlash) {
            return BASE64;
        }
        if (dashUnderscore) {
            return BASE64URL;
        }
        return notBase58 ? BASE64 : BASE58;
    }

    private static final Pattern WORD = Pattern.compile("[A-Z]?[a-z]+[0-9]*|[A-Z]+[0-9]*|[0-9]+[a-z]*");

    /** Words, numbers and acronyms joined by dashes or underscores: a file name or an identifier. */
    private static boolean isIdentifier(final String run) {
        final String[] segments = run.split("[-_]");
        if (segments.length < 3) {
            return false;
        }
        for (final String segment : segments) {
            if (segment.length() > 12 || !WORD.matcher(segment).matches()) {
                return false;
            }
        }
        return true;
    }

    private static double meanLowerRun(final String s) {
        int runs = 0;
        int inRuns = 0;
        boolean inRun = false;
        for (int i = 0; i < s.length(); i++) {
            if (Character.isLowerCase(s.charAt(i))) {
                inRuns++;
                if (!inRun) {
                    runs++;
                    inRun = true;
                }
            } else {
                inRun = false;
            }
        }
        return runs == 0 ? 0.0 : (double) inRuns / runs;
    }

    private static double letterShare(final String s) {
        final long nonSpace = s.chars().filter(c -> c != ' ').count();
        return nonSpace == 0 ? 0.0 : (double) s.chars().filter(Character::isLetter).count() / nonSpace;
    }

    private static double meanLetterRun(final String s) {
        int runs = 0;
        int inRuns = 0;
        boolean inRun = false;
        for (int i = 0; i < s.length(); i++) {
            if (Character.isLetter(s.charAt(i))) {
                inRuns++;
                if (!inRun) {
                    runs++;
                    inRun = true;
                }
            } else {
                inRun = false;
            }
        }
        return runs == 0 ? 0.0 : (double) inRuns / runs;
    }

    private static int distinctPunctuation(final String s) {
        return (int) s.chars().filter(c -> c != ' ' && !Character.isLetterOrDigit(c)).distinct().count();
    }

    private static double spaceShare(final String s) {
        return s.isEmpty() ? 0.0 : (double) s.chars().filter(c -> c == ' ').count() / s.length();
    }

    private static boolean isHex(final String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.digit(s.charAt(i), 16) < 0) {
                return false;
            }
        }
        return !s.isEmpty();
    }

    private static String describe(final String rule) {
        return switch (rule) {
            case HEX -> "hex";
            case BASE32 -> "base32";
            case BASE58 -> "base58";
            case BASE64URL -> "base64url";
            default -> "base64";
        };
    }

    private static double punctuationShare(final String s) {
        int punctuation = 0;
        int nonSpace = 0;
        for (int i = 0; i < s.length(); i++) {
            final char c = s.charAt(i);
            if (c != ' ') {
                nonSpace++;
                if (!Character.isLetterOrDigit(c)) {
                    punctuation++;
                }
            }
        }
        return nonSpace == 0 ? 0.0 : (double) punctuation / nonSpace;
    }

    private static boolean hasBothCases(final String s) {
        return !s.equals(s.toUpperCase(java.util.Locale.ROOT)) && !s.equals(s.toLowerCase(java.util.Locale.ROOT));
    }

    /**
     * At least six escapes, none further than 16 characters from the previous one. English with a URL-encoded
     * space or two stays well below; 32 characters of encoded random bytes carry seven on average.
     */
    private void dense(final Pattern escape, final String text, final Masked masked, final String rule,
            final String what, final List<DetectorFinding> out) {
        final Matcher m = escape.matcher(text);
        int count = 0;
        int start = -1;
        int end = -1;
        while (m.find()) {
            if (count > 0 && m.start() - end > 16) {
                if (count >= DENSE_ESCAPES) {
                    add(out, masked, rule, start, end, what);
                }
                count = 0;
            }
            if (count == 0) {
                start = m.start();
            }
            end = m.end();
            count++;
        }
        if (count >= DENSE_ESCAPES) {
            add(out, masked, rule, start, end, what);
        }
    }

    private static void each(final Pattern pattern, final String text,
            final java.util.function.Consumer<Matcher> action) {
        final Matcher m = pattern.matcher(text);
        while (m.find()) {
            action.accept(m);
        }
    }

    private static void add(final List<DetectorFinding> out, final Masked masked, final String rule,
            final int start, final int end, final String what) {
        final int[] span = masked.toSource(start, end);
        out.add(new DetectorFinding(rule, Stage.TEXT, Severity.BLOCKING, CATEGORY, span[0], span[1],
                "The text carries " + what + " (" + (end - start) + " characters). Encoded data may not be sent; "
                        + "describe it in words instead."));
    }

}
