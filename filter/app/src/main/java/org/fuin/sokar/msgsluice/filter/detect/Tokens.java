package org.fuin.sokar.msgsluice.filter.detect;

import java.util.ArrayList;
import java.util.List;

/** Whitespace-separated tokens, without the sentence punctuation around them. */
final class Tokens {

    private static final String TRIM = ".,;:!?()[]{}\"'`*<>";

    private Tokens() {
    }

    /** Each token as {@code [start, end)} into {@code text}. */
    static List<int[]> of(final String text) {
        final List<int[]> tokens = new ArrayList<>();
        int i = 0;
        while (i < text.length()) {
            while (i < text.length() && Character.isWhitespace(text.charAt(i))) {
                i++;
            }
            int start = i;
            while (i < text.length() && !Character.isWhitespace(text.charAt(i))) {
                i++;
            }
            int end = i;
            while (start < end && TRIM.indexOf(text.charAt(start)) >= 0) {
                start++;
            }
            while (end > start && TRIM.indexOf(text.charAt(end - 1)) >= 0) {
                end--;
            }
            if (end > start) {
                tokens.add(new int[] {start, end});
            }
        }
        return tokens;
    }

    static boolean isVowel(final char c) {
        return "aeiouyAEIOUY".indexOf(c) >= 0;
    }

}
