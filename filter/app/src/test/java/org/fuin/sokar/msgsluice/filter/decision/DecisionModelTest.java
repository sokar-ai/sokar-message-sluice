package org.fuin.sokar.msgsluice.filter.decision;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.fuin.sokar.msgsluice.filter.decision.DecisionConfig.Mode;
import org.fuin.sokar.msgsluice.filter.decision.DecisionConfig.SuspiciousPolicy;
import org.junit.jupiter.api.Test;

/** The two decision modes against one identical set of findings. */
class DecisionModelTest {

    static Finding text(final String rule, final String category, final Severity severity) {
        return new Finding(rule, Stage.TEXT, severity, category, "parts[0].text", 0, 0, 4, "****", "because",
                List.of(), "test");
    }

    static final Finding HEX = text("ENCODING/HEX", "ENCODED_DATA", Severity.SUSPICIOUS);

    static final Finding EMAIL = text("SENSITIVE/EMAIL", "EMAIL", Severity.SUSPICIOUS);

    static final Finding KEY = text("SENSITIVE/CLOUD_KEY", "CLOUD_KEY", Severity.BLOCKING);

    static DecisionConfig config(final Mode mode, final SuspiciousPolicy policy, final Map<String, Double> weights,
            final Set<String> disabled, final Map<String, Severity> overrides) {
        return new DecisionConfig(mode, policy, 2, 4.0, weights, disabled, overrides);
    }

    static boolean rejects(final DecisionConfig config, final Finding... findings) {
        return !new DecisionModel(config).decide(List.of(findings), true).accepted();
    }

    @Test
    void thresholdCombinesOnlyDifferentRules() {
        final DecisionConfig combine = DecisionConfig.defaults();
        assertThat(rejects(combine, HEX, HEX, HEX)).isFalse();
        assertThat(rejects(combine, HEX, EMAIL)).isTrue();
        assertThat(rejects(combine, KEY)).isTrue();
        assertThat(rejects(config(Mode.THRESHOLD, SuspiciousPolicy.IGNORE, Map.of(), Set.of(), Map.of()), HEX,
                EMAIL)).isFalse();
        assertThat(rejects(config(Mode.THRESHOLD, SuspiciousPolicy.REJECT, Map.of(), Set.of(), Map.of()), HEX))
                .isTrue();
    }

    @Test
    void scoreAddsWeakSignalsUp() {
        final DecisionConfig score = config(Mode.SCORE, SuspiciousPolicy.COMBINE, Map.of(), Set.of(), Map.of());
        assertThat(rejects(score, HEX, EMAIL)).isFalse();
        assertThat(rejects(score, HEX, HEX, EMAIL, EMAIL)).isTrue();
        assertThat(rejects(score, KEY)).isTrue();
    }

    @Test
    void aDisabledRuleOrAWeightOfZeroSwitchesARuleOffInFact() {
        assertThat(rejects(config(Mode.THRESHOLD, SuspiciousPolicy.COMBINE, Map.of(), Set.of(KEY.ruleId()),
                Map.of()), KEY)).isFalse();
        assertThat(rejects(config(Mode.SCORE, SuspiciousPolicy.COMBINE, Map.of(KEY.ruleId(), 0.0), Set.of(),
                Map.of()), KEY)).isFalse();
    }

    @Test
    void aCategoryCanBeRegraded() {
        assertThat(rejects(config(Mode.THRESHOLD, SuspiciousPolicy.COMBINE, Map.of(), Set.of(),
                Map.of("CLOUD_KEY", Severity.INFO)), KEY)).isFalse();
        assertThat(rejects(config(Mode.THRESHOLD, SuspiciousPolicy.COMBINE, Map.of(), Set.of(),
                Map.of("EMAIL", Severity.BLOCKING)), EMAIL)).isTrue();
    }

    @Test
    void theEnvelopeCannotBeConfiguredAwayAndRefusesWhileOnlyReporting() {
        final Finding raw = Finding.envelope("ENVELOPE/RAW_PART_NOT_ALLOWED", Severity.BLOCKING, "parts[0].raw", 0,
                "binary");
        final DecisionConfig lenient = config(Mode.SCORE, SuspiciousPolicy.IGNORE,
                Map.of("ENVELOPE/RAW_PART_NOT_ALLOWED", 0.0), Set.of("ENVELOPE/RAW_PART_NOT_ALLOWED"),
                Map.of("ENVELOPE", Severity.INFO));
        final Verdict verdict = new DecisionModel(lenient).decide(List.of(raw), false);
        assertThat(verdict.accepted()).isFalse();
        assertThat(verdict.decidingRule()).isEqualTo("ENVELOPE/RAW_PART_NOT_ALLOWED");
    }

    @Test
    void reportingAcceptsButSaysWhatBlockingWouldRefuse() {
        final Verdict verdict = new DecisionModel(DecisionConfig.defaults()).decide(List.of(KEY), false);
        assertThat(verdict.accepted()).isTrue();
        assertThat(verdict.wouldReject()).isTrue();
        assertThat(verdict.decidingRule()).isEqualTo(KEY.ruleId());
    }

}
