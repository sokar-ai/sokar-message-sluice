package org.fuin.sokar.msgsluice.filter.detect;

import java.util.Objects;

/**
 * One piece of text handed to a detector.
 *
 * @param location  where it sits in the message, for example {@code parts[0].text} or {@code metadata.note}
 * @param partIndex the index of its part, or -1 for text outside the parts
 * @param text      the text itself; offsets in a finding count UTF-16 units into exactly this string
 */
public record TextUnderCheck(String location, int partIndex, String text) {

    public TextUnderCheck {
        Objects.requireNonNull(location, "location");
        Objects.requireNonNull(text, "text");
    }

}
