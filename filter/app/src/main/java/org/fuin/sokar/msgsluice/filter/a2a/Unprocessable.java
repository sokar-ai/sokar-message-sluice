package org.fuin.sokar.msgsluice.filter.a2a;

import java.util.Objects;

/**
 * A file that cannot be judged as a message at all. It goes to {@code error/} and still gets a rejection.
 * The message never quotes the file: it is built from fixed text, a rule id and at most a position.
 */
public final class Unprocessable extends Exception {

    private static final long serialVersionUID = 1L;

    private final String ruleId;

    public Unprocessable(final String ruleId, final String reason) {
        super(reason, null, false, false);
        this.ruleId = Objects.requireNonNull(ruleId, "ruleId");
    }

    /** For example {@code UNPROCESSABLE/MALFORMED_JSON}. */
    public String ruleId() {
        return ruleId;
    }

    /** The English explanation, safe to put into an answer. */
    public String reason() {
        return Objects.requireNonNull(getMessage());
    }

}
