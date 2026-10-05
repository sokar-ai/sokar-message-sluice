package org.fuin.sokar.msgsluice.filter.decision;

import java.util.Map;
import java.util.Set;

/**
 * How findings become a verdict.
 *
 * @param mode                   {@code THRESHOLD} or {@code SCORE}
 * @param suspiciousPolicy       what {@code SUSPICIOUS} findings do in {@code THRESHOLD} mode
 * @param suspiciousCombineCount how many different rules must be suspicious to reject under {@code COMBINE}
 * @param scoreThreshold         the score from which {@code SCORE} mode rejects
 * @param weights                per rule id; a rule without an entry weighs 1.0
 * @param disabledRules          rule ids whose findings are dropped before deciding
 * @param severityOverrides      per category, replacing the severity a detector reported
 */
public record DecisionConfig(Mode mode, SuspiciousPolicy suspiciousPolicy, int suspiciousCombineCount,
        double scoreThreshold, Map<String, Double> weights, Set<String> disabledRules,
        Map<String, Severity> severityOverrides) {

    public enum Mode {
        THRESHOLD, SCORE
    }

    public enum SuspiciousPolicy {
        IGNORE, COMBINE, REJECT
    }

    public DecisionConfig {
        weights = Map.copyOf(weights);
        disabledRules = Set.copyOf(disabledRules);
        severityOverrides = Map.copyOf(severityOverrides);
        if (suspiciousCombineCount < 1) {
            throw new IllegalArgumentException("suspiciousCombineCount must be at least 1: " + suspiciousCombineCount);
        }
    }

    /** The defaults of the design. */
    public static DecisionConfig defaults() {
        return new DecisionConfig(Mode.THRESHOLD, SuspiciousPolicy.COMBINE, 2, 4.0, Map.of(), Set.of(), Map.of());
    }

}
