package org.fuin.sokar.msgsluice.filter.detect;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;

import org.fuin.sokar.msgsluice.filter.decision.DecisionConfig;
import org.fuin.sokar.msgsluice.filter.decision.DecisionModel;
import org.fuin.sokar.msgsluice.filter.decision.Finding;
import org.fuin.sokar.msgsluice.filter.decision.Redactor;
import org.fuin.sokar.msgsluice.filter.decision.Verdict;
import org.fuin.sokar.msgsluice.filter.ConfigException;
import org.fuin.sokar.msgsluice.filter.Settings;
import org.junit.jupiter.api.Test;

/**
 * The detectors' rates, measured: false positives against real English, and false negatives from 32 characters of
 * payload per encoding. The English is a snapshot of every paragraph of this repository's own documentation -
 * prose written by agents, with code spans, paths, rule ids and numbers in it, which is what the filter will see.
 */
class EncodedPayloadRatesTest {

    /** The detectors exactly as the default configuration builds them. */
    static final DetectorRunner RUNNER = new DetectorRunner(defaultDetectors(), new Redactor(Redactor.Mode.PARTIAL));

    static List<ContentDetector> defaultDetectors() {
        try {
            return Settings.load(null, Map.of("mail", "/m")).detectors();
        } catch (final ConfigException ex) {
            throw new IllegalStateException(ex);
        }
    }

    static final DecisionModel MODEL = new DecisionModel(DecisionConfig.defaults());

    static Verdict judge(final String text) {
        final List<Finding> findings = RUNNER.run(List.of(new TextUnderCheck("parts[0].text", 0, text)));
        return MODEL.decide(findings, true);
    }

    /** The frozen corpus's size: a different count means the reference set itself changed. */
    static final int CORPUS_PARAGRAPHS = 285;

    /**
     * The English, frozen as a test resource (paragraphs separated by one blank line): taken from the documentation
     * once, so that deleting a finished issue or editing a page cannot move a rate, and where the checkout sits
     * cannot empty the set.
     */
    static List<String> englishCorpus() throws Exception {
        final String text;
        try (InputStream in = EncodedPayloadRatesTest.class.getResourceAsStream("/english-corpus.txt")) {
            assertThat(in).as("english-corpus.txt on the test class path").isNotNull();
            text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        final List<String> paragraphs = Arrays.stream(text.split("\n\n")).map(String::strip)
                .filter(p -> !p.isEmpty()).toList();
        assertThat(paragraphs).as("English corpus").hasSize(CORPUS_PARAGRAPHS);
        return paragraphs;
    }

    @Test
    void englishIsAcceptedAndThirtyTwoCharactersOfEveryEncodingAreNot() throws Exception {
        final List<String> english = englishCorpus();
        final List<String> refused = english.stream().filter(t -> !judge(t).accepted()).toList();
        System.out.printf("english: %d texts, %d refused%n", english.size(), refused.size());
        assertThat(refused.size()).as("false positives, %s", refused).isLessThan(english.size() / 100 + 1);

        final Random random = new Random(42);
        for (final int length : new int[] {32, 48, 64}) {
            for (final Map.Entry<String, Function<Random, String>> g : Payloads.generators(length).entrySet()) {
                int missed = 0;
                for (int i = 0; i < 500; i++) {
                    final String carrier = english.get(random.nextInt(english.size()));
                    final String text = carrier.substring(0, Math.min(120, carrier.length())) + " Here it is: "
                            + g.getValue().apply(random) + " - thanks.";
                    if (judge(text).accepted()) {
                        missed++;
                    }
                }
                System.out.printf("%3d %-17s missed %3d / 500%n", length, g.getKey(), missed);
                assertThat(missed).as("%s at %d characters", g.getKey(), length).isLessThan(5);
            }
        }
    }

}
