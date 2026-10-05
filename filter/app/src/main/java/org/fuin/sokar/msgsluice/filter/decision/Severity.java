package org.fuin.sokar.msgsluice.filter.decision;

/** How much a finding weighs. The order matters: a later constant is more severe. */
public enum Severity {

    INFO(0.25), SUSPICIOUS(1.0), BLOCKING(4.0);

    private final double factor;

    Severity(final double factor) {
        this.factor = factor;
    }

    /** The factor a finding contributes in the {@code SCORE} decision mode. */
    public double factor() {
        return factor;
    }

}
