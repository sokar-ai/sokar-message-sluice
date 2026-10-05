package org.fuin.sokar.msgsluice.filter.detect;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

/** Letters distributed unlike English, and text with too little whitespace. */
class DistributionDetectorTest {

    private final DistributionDetector detector = new DistributionDetector(64, 1.0, 0.1);

    private List<DetectorFinding> inspect(final String text) {
        return detector.inspect(new TextUnderCheck("parts[0].text", 0, text));
    }

    @Test
    void aTextWithoutLettersSaysSoRatherThanNamingANumberItNeverComputed() {
        // Not one letter from a to z: the chi-squared test has nothing to count.
        final String cyrillic = "Фильтр читает каждое сообщение, прежде чем оно уйдёт. ".repeat(3);

        assertThat(inspect(cyrillic)).filteredOn(f -> f.ruleId().equals(DistributionDetector.LETTERS))
                .singleElement().satisfies(f -> {
                    assertThat(f.reason()).doesNotContain("Infinity").contains("no letters");
                });
    }

    @Test
    void englishProseIsNotFound() {
        assertThat(inspect("The filter reads every message before it leaves, and it refuses what it cannot "
                + "account for as ordinary English prose written by one of the agents.")).isEmpty();
    }

}
