package org.fuin.sokar.msgsluice.filter.detect;

import java.util.Objects;

import org.fuin.sokar.msgsluice.filter.decision.Severity;
import org.fuin.sokar.msgsluice.filter.decision.Stage;

/**
 * What a detector reports. It carries offsets and never an excerpt, so that a detector cannot put what it
 * matched into an answer even by mistake: the frame cuts the excerpt and redacts it.
 *
 * @param ruleId   {@code CATEGORY/RULE}, upper case, for example {@code ENCODING/LONG_TOKEN}
 * @param stage    {@link Stage#TEXT} or {@link Stage#CONTEXT}
 * @param severity the default severity; the configuration may re-grade it by category
 * @param category what kind of thing was found
 * @param start    first offset of the match in {@link TextUnderCheck#text()}
 * @param end      offset after the last character of the match
 * @param reason   English, for the agent that sent the message; must not quote the match
 */
public record DetectorFinding(String ruleId, Stage stage, Severity severity, String category, int start, int end,
        String reason) {

    public DetectorFinding {
        Objects.requireNonNull(ruleId, "ruleId");
        Objects.requireNonNull(stage, "stage");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(category, "category");
        Objects.requireNonNull(reason, "reason");
    }

}
