package org.fuin.sokar.msgsluice.filter.decision;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.Nullable;

/**
 * Turns findings into a verdict. Detectors only ever report; this is the one place that decides.
 */
public final class DecisionModel {

    private final DecisionConfig config;

    public DecisionModel(final DecisionConfig config) {
        this.config = Objects.requireNonNull(config, "config");
    }

    /**
     * @param reported every finding, envelope and detectors alike
     * @param blocking {@code false} while the directory only reports: content findings are then recorded but
     *                 never refuse. An envelope finding refuses in both modes, because it is a format decision
     *                 and not a heuristic.
     */
    public Verdict decide(final List<Finding> reported, final boolean blocking) {
        final List<Finding> findings = new ArrayList<>();
        for (final Finding finding : reported) {
            // The envelope is not configurable away: a payload part is a data transfer by definition.
            if (finding.stage().alwaysRefuses()) {
                findings.add(finding);
            } else if (!config.disabledRules().contains(finding.ruleId())) {
                final Severity override = config.severityOverrides().get(finding.category());
                findings.add(override == null ? finding : finding.withSeverity(override));
            }
        }

        final String envelopeRule = findings.stream()
                .filter(f -> f.stage().alwaysRefuses() && f.severity() == Severity.BLOCKING)
                .map(Finding::ruleId).findFirst().orElse(null);
        // Everything but a blocking envelope finding is weighed, a suspicious envelope finding included.
        final List<Finding> weighed = findings.stream()
                .filter(f -> !f.stage().alwaysRefuses() || f.severity() != Severity.BLOCKING).toList();
        final String weighedRule = config.mode() == DecisionConfig.Mode.SCORE ? byScore(weighed) : byThreshold(weighed);

        final String rule = envelopeRule != null ? envelopeRule : weighedRule;
        final boolean accepted = blocking ? rule == null : envelopeRule == null;
        return new Verdict(accepted, rule != null, rule, findings);
    }

    private @Nullable String byThreshold(final List<Finding> findings) {
        for (final Finding finding : findings) {
            if (finding.severity() == Severity.BLOCKING) {
                return finding.ruleId();
            }
        }
        final Set<String> suspicious = new LinkedHashSet<>();
        findings.stream().filter(f -> f.severity() == Severity.SUSPICIOUS).forEach(f -> suspicious.add(f.ruleId()));
        return switch (config.suspiciousPolicy()) {
            case IGNORE -> null;
            case REJECT -> suspicious.isEmpty() ? null : suspicious.iterator().next();
            // Different rules, so that one rule cannot reject on its own by repeating itself.
            case COMBINE -> suspicious.size() >= config.suspiciousCombineCount() ? suspicious.iterator().next() : null;
        };
    }

    private @Nullable String byScore(final List<Finding> findings) {
        double score = 0.0;
        String heaviest = null;
        double heaviestContribution = 0.0;
        for (final Finding finding : findings) {
            final double contribution = config.weights().getOrDefault(finding.ruleId(), 1.0)
                    * finding.severity().factor();
            score += contribution;
            if (contribution > heaviestContribution) {
                heaviestContribution = contribution;
                heaviest = finding.ruleId();
            }
        }
        return score >= config.scoreThreshold() ? heaviest : null;
    }

}
