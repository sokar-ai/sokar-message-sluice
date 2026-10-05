package org.fuin.sokar.msgsluice.filter;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.fuin.sokar.msgsluice.filter.detect.EntropyDetector;
import org.fuin.sokar.msgsluice.filter.detect.TextUnderCheck;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CalibrationTest {

    @TempDir
    Path tmp;

    static String prose(final int i) {
        return "Message " + i + ": the build is green again, and the retry moved into the scheduler. The suite now "
                + "takes four minutes instead of nine, which is what we wanted before the release on Thursday. "
                + "Please review the change and say whether the new timeout is long enough for the slow machines.";
    }

    static List<Path> listed(final Path dir) throws Exception {
        try (Stream<Path> files = Files.list(dir)) {
            return files.sorted().toList();
        }
    }

    @Test
    void calibrationMeasuresTheSameWindowsAsTheDetectorTheTailIncluded() {
        // 64 plain letters, then six different ones: only a window ending at the text's end sees them.
        final String text = "a".repeat(64) + "qwerty";
        final EntropyDetector detector = new EntropyDetector(0.5, 64, 16, 16);

        assertThat(detector.inspect(new TextUnderCheck("t", 0, text))).isNotEmpty();
        assertThat(Calibration.maxEntropy(text, 64, 16)).isGreaterThan(0.5);
    }

    @Test
    void itMovesNothingAndPrintsAConfigurationTheFilterReads() throws Exception {
        final Path dir = Files.createDirectory(tmp.resolve("sent"));
        for (int i = 0; i < 40; i++) {
            Files.writeString(dir.resolve("m" + i + ".json"), """
                    {"messageId":"m-%d","role":"ROLE_AGENT","parts":[{"text":"%s"}]}""".formatted(i, prose(i)));
        }
        final List<Path> before = listed(dir);

        final String report = new Calibration(Settings.load(null, Map.of("mail", tmp.toString())))
                .run(dir);

        assertThat(listed(dir)).isEqualTo(before);
        assertThat(report).contains("40 messages").contains("would refuse 0")
                .contains("detector.entropy.threshold=").contains("detector.distribution.minWhitespaceShare=");
        final Path properties = Files.writeString(tmp.resolve("calibrated.properties"), report);
        final Settings calibrated = Settings.load(properties, Map.of("mail", tmp.toString()));
        assertThat(Double.parseDouble(calibrated.value("detector.entropy.threshold"))).isBetween(3.0, 5.5);
        assertThat(Double.parseDouble(calibrated.value("detector.distribution.maxChiSquarePerLetter")))
                .isLessThan(2.7);
    }

}
