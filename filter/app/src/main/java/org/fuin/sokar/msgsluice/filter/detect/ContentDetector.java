package org.fuin.sokar.msgsluice.filter.detect;

import java.util.List;
import java.util.Set;

/**
 * The seam between the frame and what looks at the text. An implementation reports; it never sees the
 * envelope and never decides. Implementations must be stateless and thread-safe.
 */
public interface ContentDetector {

    /** Names the detector and its version in every receipt, for example {@code builtin/long-token@1}. */
    String id();

    /** Every rule id this detector can report, so a configuration naming another one is caught at startup. */
    Set<String> ruleIds();

    /** Every category this detector can report, for the same reason. */
    Set<String> categories();

    /** Inspects one text. Returns an empty list when there is nothing to report. */
    List<DetectorFinding> inspect(TextUnderCheck text);

}
