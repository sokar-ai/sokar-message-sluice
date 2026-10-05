package org.fuin.sokar.msgsluice.filter.detect;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.fuin.sokar.msgsluice.filter.decision.Finding;
import org.junit.jupiter.api.Test;

/**
 * A text as long as a part may be, in every shape a repeated regular-expression group could take one step per
 * repetition over: a check that cannot run refuses even while only reporting, so it must never run out of stack.
 */
class LongInputTest {

    /** Just below the default limit of a text part. */
    static final int LENGTH = 64 * 1000;

    static Map<String, String> shapes() {
        final Map<String, String> shapes = new LinkedHashMap<>();
        shapes.put("capitals", "PLEASE READ THE STATUS REPORT. ");
        shapes.put("number list", "12, 34, ");
        shapes.put("hex list", "0x12, 0x34, ");
        shapes.put("byte list", "de:ad:be:ef:");
        shapes.put("binary", "01010101 ");
        shapes.put("thousands", "1,000,");
        shapes.put("data uri parameters", ";charset=utf-8");
        shapes.put("percent", "%41");
        shapes.put("quoted-printable", "=41");
        shapes.put("single spaces", "A B ");
        shapes.put("punctuation", "!#$%&()*+,-./:;<=>?@[]^_");
        shapes.put("url path", "https://example.org/" + "a/".repeat(10));
        return shapes;
    }

    static String repeat(final String unit) {
        return unit.repeat(LENGTH / unit.length() + 1).substring(0, LENGTH);
    }

    @Test
    void noShapeOfAnyLengthMakesACheckFail() {
        for (final Map.Entry<String, String> shape : shapes().entrySet()) {
            String text = repeat(shape.getValue());
            if (shape.getKey().equals("data uri parameters")) {
                text = "data:text/plain" + text;
            }
            final List<Finding> findings = EncodedPayloadRatesTest.RUNNER
                    .run(List.of(new TextUnderCheck("parts[0].text", 0, text)));
            assertThat(findings).as(shape.getKey()).extracting(Finding::ruleId)
                    .doesNotContain(DetectorRunner.DETECTOR_FAILED, DetectorRunner.UNREDACTABLE);
        }
    }

}
