package org.fuin.sokar.msgsluice.filter.decision;

import java.util.List;

import org.jspecify.annotations.Nullable;

/**
 * What the filter does with one message.
 *
 * @param accepted     whether the message moves on
 * @param wouldReject  whether blocking mode would have refused it; differs from {@code !accepted} only while
 *                     a directory is reporting rather than blocking
 * @param decidingRule the rule the refusal traces back to, or {@code null} when nothing would refuse
 * @param findings     every finding that counted, in the order they were made
 */
public record Verdict(boolean accepted, boolean wouldReject, @Nullable String decidingRule, List<Finding> findings) {

    public Verdict {
        findings = List.copyOf(findings);
    }

}
