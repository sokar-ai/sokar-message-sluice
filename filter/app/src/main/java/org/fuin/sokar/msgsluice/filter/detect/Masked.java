package org.fuin.sokar.msgsluice.filter.detect;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jspecify.annotations.Nullable;

/**
 * A text with its known-legitimate shapes taken out, for the checks that ask whether text looks like English:
 * URLs without their query, up to four isolated UUIDs, an IPv4 address, numbers, dates, times and compact ISO
 * timestamps, currency amounts, acronyms of up to
 * six capitals, and a few short commit hashes. Each masked span becomes one space, so it separates tokens without adding statistics of its own.
 *
 * <p>
 * Deliberately not masked: a URL's query and fragment, where a payload would sit; a URL path with a segment
 * longer than {@value #MAX_PATH_SEGMENT} characters, or one that makes the URL longer than
 * {@value #MAX_MASKED_URL}; any part of a URL whose host no DNS name could be, and a host label of
 * {@value #LONG_LABEL} characters or more; a UUID next to another UUID, since a chain of them is hex;
 * every UUID of a text that carries more than {@value #MAX_UUIDS}, however they are separated;
 * and hashes, keys and e-mail addresses. A credential check must never see a masked text.
 */
public final class Masked {

    /** No path segment of an ordinary URL is longer; a longer one is checked like any other token. */
    static final int MAX_PATH_SEGMENT = 48;

    /** Scheme, host and path together; a longer URL keeps its path, which is then checked like any text. */
    static final int MAX_MASKED_URL = 256;

    /** The longest name DNS can hold, and the longest label in it. */
    static final int MAX_HOST = 253;

    static final int MAX_LABEL = 63;

    /**
     * From this length on, a host label stays for the checks to judge: four labels of 63 hex characters are a
     * valid name and 126 bytes of payload.
     */
    static final int LONG_LABEL = 16;

    private static final Pattern URL = Pattern.compile("(?i)\\bhttps?://[^\\s<>\"'`]+");

    private static final Pattern UUID = Pattern
            .compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    private static final Pattern DATE = Pattern.compile("(?<![\\w.])\\d{4}-\\d{2}-\\d{2}"
            + "(?:[T ]\\d{2}:\\d{2}(?::\\d{2}(?:\\.\\d{1,9})?)?(?:Z|[+-]\\d{2}:?\\d{2})?)?(?![\\w])");

    private static final Pattern TIME = Pattern
            .compile("(?<![\\w.:])\\d{1,2}:\\d{2}(?::\\d{2}(?:\\.\\d{1,9})?)?Z?(?![\\w:])");

    /**
     * Grouped thousands of any length, or at most thirteen plain digits - a Unix time in milliseconds; a
     * 300-digit number is not masked.
     */
    private static final Pattern NUMBER = Pattern.compile("(?<![\\w.])[$€£¥]?(?:\\d{1,3}(?:[,']\\d{3})+|\\d{1,13})"
            + "(?:\\.\\d{1,4})?(?:%|[kKmMbB]|ms|s|h)?(?![\\w])");

    /** 20260916T082314Z, the compact ISO form - how this filter itself names its answers. */
    private static final Pattern BASIC_TIMESTAMP = Pattern
            .compile("(?<![0-9])\\d{8}T\\d{4}(?:\\d{2}(?:\\d{1,9})?)?Z?(?![0-9])");

    private static final Pattern IPV4 = Pattern
            .compile("(?<![\\w.])(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}(?![\\w.])");

    private static final Pattern ACRONYM = Pattern.compile("(?<![\\w])[A-Z]{2,6}s?(?![\\w])");

    /** A short commit hash, as agents name commits. Not masked when there are many: then they are a payload. */
    private static final Pattern SHORT_HASH = Pattern
            .compile("(?<![0-9A-Za-z])(?=[0-9a-f]*[0-9])(?=[0-9a-f]*[a-f])[0-9a-f]{7,12}(?![0-9A-Za-z])");

    static final int MAX_SHORT_HASHES = 8;

    /** At most this many UUIDs in one text are masked as ids; with more, none is. */
    static final int MAX_UUIDS = 4;

    private final String source;

    private final String text;

    private final int[] from;

    private final int[] to;

    private Masked(final String source, final String text, final int[] from, final int[] to) {
        this.source = source;
        this.text = text;
        this.from = from;
        this.to = to;
    }

    public static Masked of(final String source) {
        return of(source, true);
    }

    /**
     * @param everything {@code false} masks only URLs, isolated UUIDs, IPv4 addresses and compact ISO
     *                   timestamps: numbers, dates and acronyms stay, for
     *                   the checks that recognize an encoding by its alphabet, where a run of 0 and 1 is a number
     *                   to everything else
     */
    public static Masked of(final String source, final boolean everything) {
        final List<int[]> spans = new ArrayList<>();
        final Matcher url = URL.matcher(source);
        while (url.find()) {
            urlSpan(source, url.start(), url.end(), spans);
        }
        // An address or a timestamp is not an encoding. A credential check sees them, since it never masks.
        for (final Pattern always : List.of(IPV4, BASIC_TIMESTAMP)) {
            final Matcher m = always.matcher(source);
            while (m.find()) {
                spans.add(new int[] {m.start(), m.end()});
            }
        }
        // A few ids are ids. Many are 16 bytes of data each, however they are separated, so past the limit
        // none is masked and the hex checks see all of them.
        final List<int[]> uuids = new ArrayList<>();
        final Matcher uuid = UUID.matcher(source);
        while (uuid.find()) {
            uuids.add(new int[] {uuid.start(), uuid.end()});
        }
        if (uuids.size() <= MAX_UUIDS) {
            for (final int[] u : uuids) {
                if (!touchesUuid(source, u[0], u[1])) {
                    spans.add(u);
                }
            }
        }
        for (final Pattern pattern : everything ? List.of(DATE, TIME, NUMBER, ACRONYM) : List.<Pattern>of()) {
            final Matcher m = pattern.matcher(source);
            while (m.find()) {
                spans.add(new int[] {m.start(), m.end()});
            }
        }
        if (everything) {
            final List<int[]> hashes = new ArrayList<>();
            final Matcher m = SHORT_HASH.matcher(source);
            while (m.find()) {
                hashes.add(new int[] {m.start(), m.end()});
            }
            if (hashes.size() <= MAX_SHORT_HASHES) {
                spans.addAll(hashes);
            }
        }
        spans.sort(Comparator.comparingInt(s -> s[0]));

        final StringBuilder out = new StringBuilder(source.length());
        final List<Integer> from = new ArrayList<>(source.length());
        final List<Integer> to = new ArrayList<>(source.length());
        int i = 0;
        int span = 0;
        while (i < source.length()) {
            while (span < spans.size() && spans.get(span)[1] <= i) {
                span++;
            }
            if (span < spans.size() && spans.get(span)[0] <= i) {
                int end = spans.get(span)[1];
                while (span + 1 < spans.size() && spans.get(span + 1)[0] < end) {
                    end = Math.max(end, spans.get(++span)[1]);
                }
                out.append(' ');
                from.add(i);
                to.add(end);
                i = end;
                span++;
                continue;
            }
            out.append(source.charAt(i));
            from.add(i);
            to.add(i + 1);
            i++;
        }
        return new Masked(source, out.toString(), from.stream().mapToInt(Integer::intValue).toArray(),
                to.stream().mapToInt(Integer::intValue).toArray());
    }

    /**
     * Scheme, host and path are masked; the query and fragment stay. A path with an overlong segment, or one that
     * makes the URL longer than {@value #MAX_MASKED_URL} characters, stays. A host that no DNS name could be is
     * not masked at all, and a host label of {@value #LONG_LABEL} characters or more stays, so that the checks
     * judge it as the token it is.
     */
    private static void urlSpan(final String source, final int start, final int rawEnd, final List<int[]> spans) {
        int end = rawEnd;
        // Sentence punctuation after a URL is not part of it.
        while (end > start && ".,;:!?)]}".indexOf(source.charAt(end - 1)) >= 0) {
            end--;
        }
        final String url = source.substring(start, end);
        int cut = url.length();
        for (final char c : new char[] {'?', '#'}) {
            final int at = url.indexOf(c);
            if (at >= 0) {
                cut = Math.min(cut, at);
            }
        }
        final int scheme = url.indexOf("://") + 3;
        final int pathStart = url.indexOf('/', scheme);
        final int hostEnd = pathStart < 0 || pathStart > cut ? cut : pathStart;
        final List<int[]> longLabels = hostLabels(url, scheme, hostEnd);
        if (longLabels == null) {
            return;
        }
        boolean pathIsPlain = true;
        if (pathStart >= 0 && pathStart < cut) {
            for (final String segment : url.substring(pathStart, cut).split("/")) {
                pathIsPlain &= segment.length() <= MAX_PATH_SEGMENT;
            }
        }
        final int maskEnd = pathIsPlain && cut <= MAX_MASKED_URL ? cut : hostEnd;
        int from = 0;
        for (final int[] label : longLabels) {
            if (label[0] > from) {
                spans.add(new int[] {start + from, start + label[0]});
            }
            from = label[1];
        }
        if (maskEnd > from) {
            spans.add(new int[] {start + from, start + maskEnd});
        }
    }

    /**
     * The labels of {@code url[from, to)} that are {@value #LONG_LABEL} characters or longer, or {@code null} when
     * it is not a name DNS could hold with an optional port: at most {@value #MAX_HOST} characters, labels of 1 to
     * {@value #MAX_LABEL} letters, digits and dashes. An IPv4 address is such a name too.
     */
    static @Nullable List<int[]> hostLabels(final String url, final int from, final int to) {
        int hostEnd = to;
        final int colon = url.lastIndexOf(':', to - 1);
        if (colon >= from) {
            final String port = url.substring(colon + 1, to);
            if (port.isEmpty() || port.length() > 5 || !port.chars().allMatch(c -> c >= '0' && c <= '9')) {
                return null;
            }
            hostEnd = colon;
        }
        if (hostEnd == from || hostEnd - from > MAX_HOST) {
            return null;
        }
        final List<int[]> longLabels = new ArrayList<>();
        int labelStart = from;
        for (int i = from; i <= hostEnd; i++) {
            if (i == hostEnd || url.charAt(i) == '.') {
                final int length = i - labelStart;
                if (length == 0 || length > MAX_LABEL) {
                    return null;
                }
                if (length >= LONG_LABEL) {
                    longLabels.add(new int[] {labelStart, i});
                }
                labelStart = i + 1;
                continue;
            }
            final char c = url.charAt(i);
            if (!(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-')) {
                return null;
            }
        }
        return longLabels;
    }

    private static boolean touchesUuid(final String source, final int start, final int end) {
        final int before = Math.max(0, start - 37);
        final int after = Math.min(source.length(), end + 37);
        final Matcher left = UUID.matcher(source.substring(before, start));
        int lastEnd = -1;
        while (left.find()) {
            lastEnd = left.end();
        }
        final Matcher right = UUID.matcher(source.substring(end, after));
        return lastEnd >= 0 && lastEnd >= start - before - 1 || right.find() && right.start() <= 1;
    }

    /** The masked text: what the statistics are computed over. */
    public String text() {
        return text;
    }

    /** The text before masking. */
    public String source() {
        return source;
    }

    /** The span of the source that {@code [start, end)} of the masked text covers. */
    public int[] toSource(final int start, final int end) {
        return new int[] {from[start], to[end - 1]};
    }

}
