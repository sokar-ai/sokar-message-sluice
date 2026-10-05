package org.fuin.sokar.msgsluice.filter.decision;

import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.Nullable;

/**
 * One reason, as it appears in an answer. The excerpt is already redacted: a {@code Finding} is the
 * shape that leaves the house, so nothing in it may hold what a rule matched in clear text.
 *
 * @param ruleId          the rule that fired, for example {@code ENCODING/LONG_TOKEN}
 * @param stage           where it was found
 * @param severity        the severity after any configured override
 * @param category        what kind of thing was found
 * @param location        where in the message, for example {@code parts[0].text}; {@code null} for the file itself
 * @param partIndex       the part's index, or -1 when the finding is not about a part
 * @param start           first offset in the text at {@code location}, or -1
 * @param end             offset after the last character, or -1
 * @param redactedExcerpt what was matched, masked; {@code null} when the rule matched no text
 * @param reason          the English explanation for the agent that sent the message
 * @param relatedMessageIds for a correlation finding, every message involved
 * @param detector        the detector that reported it, or {@code envelope}
 */
public record Finding(String ruleId, Stage stage, Severity severity, String category,
        @Nullable String location, int partIndex, int start, int end, @Nullable String redactedExcerpt,
        String reason, List<String> relatedMessageIds, String detector) {

    public Finding {
        Objects.requireNonNull(ruleId, "ruleId");
        Objects.requireNonNull(stage, "stage");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(category, "category");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(detector, "detector");
        relatedMessageIds = List.copyOf(relatedMessageIds);
    }

    /** A finding about the structure of the message, which matched no text. */
    public static Finding envelope(final String ruleId, final Severity severity, final @Nullable String location,
            final int partIndex, final String reason) {
        return new Finding(ruleId, Stage.ENVELOPE, severity, "ENVELOPE", location, partIndex, -1, -1, null, reason,
                List.of(), "envelope");
    }

    /** A finding about a check that could not be completed. It always refuses. */
    public static Finding frame(final String ruleId, final @Nullable String location, final int partIndex,
            final String reason, final String detector) {
        return new Finding(ruleId, Stage.FRAME, Severity.BLOCKING, "FRAME", location, partIndex, -1, -1, null, reason,
                List.of(), detector);
    }

    /** The same finding at another name for the same location. */
    public Finding withLocation(final @Nullable String other) {
        return new Finding(ruleId, stage, severity, category, other, partIndex, start, end, redactedExcerpt, reason,
                relatedMessageIds, detector);
    }

    /** The same finding with another severity. */
    public Finding withSeverity(final Severity other) {
        return new Finding(ruleId, stage, other, category, location, partIndex, start, end, redactedExcerpt, reason,
                relatedMessageIds, detector);
    }

}
