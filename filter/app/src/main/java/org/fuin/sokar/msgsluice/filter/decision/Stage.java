package org.fuin.sokar.msgsluice.filter.decision;

/** Where a finding was made. */
public enum Stage {

    /** The structure of the file. Decided here, never by a detector. */
    ENVELOPE,

    /** The filter itself could not complete a check, so it fails closed. */
    FRAME,

    /** The text of one part or one metadata string, judged on its own. */
    TEXT,

    /** The text judged against what the same task already sent. */
    CONTEXT;

    /**
     * Whether a blocking finding of this stage refuses in every mode and cannot be configured away. True for
     * format decisions and for checks that could not run, never for a heuristic.
     */
    public boolean alwaysRefuses() {
        return this == ENVELOPE || this == FRAME;
    }

}
