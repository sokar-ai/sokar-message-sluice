package org.fuin.sokar.msgsluice.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.fuin.sokar.msgsluice.filter.detect.LongTokenDetector;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SettingsTest {

    @TempDir
    Path tmp;

    @Test
    void anUnknownKeyAbortsTheStartWhereverItComesFrom() throws Exception {
        final Path file = tmp.resolve("sluice.properties");
        Files.writeString(file, "mail=/x\ncheck.maxPart=3\n");

        assertThatThrownBy(() -> Settings.load(file, Map.of())).isInstanceOf(ConfigException.class)
                .hasMessageContaining("check.maxPart");
        assertThatThrownBy(() -> Settings.load(null, Map.of("mail", "/x", "decision.weight.NO/SUCH", "1")))
                .isInstanceOf(ConfigException.class).hasMessageContaining("NO/SUCH");
    }

    @Test
    void laterSourcesWinAndTheMailRootSuppliesTheDirectories() throws Exception {
        final Path file = tmp.resolve("sluice.properties");
        Files.writeString(file, "mail=/srv/mail\ncheck.maxParts=10\nblocking=true\n");

        final Settings settings = Settings.load(file, Map.of("check.maxParts", "30", "rejected", "/elsewhere"));

        assertThat(settings.config().check().maxParts()).isEqualTo(30);
        assertThat(settings.config().blocking()).isTrue();
        assertThat(settings.config().incoming()).isEqualTo(Path.of("/srv/mail/incoming"));
        assertThat(settings.config().accepted()).isEqualTo(Path.of("/srv/mail/filter/accepted"));
        assertThat(settings.config().rejected()).isEqualTo(Path.of("/elsewhere"));
        assertThat(settings.describe()).anySatisfy(l -> assertThat(l).startsWith("check.maxParts=30"));
    }

    @Test
    void theDefaultsWorkAndReportRatherThanBlock() throws Exception {
        final Settings settings = Settings.load(null, Map.of("mail", "/m"));
        assertThat(settings.config().blocking()).isFalse();
        assertThat(settings.detectors()).hasSize(5).first().isInstanceOf(LongTokenDetector.class);
    }

    @Test
    void theEnvelopeCannotBeDisabledOrRegraded() {
        assertThatThrownBy(() -> Settings.load(null,
                Map.of("mail", "/m", "decision.disabledRules", "ENVELOPE/RAW_PART_NOT_ALLOWED")))
                .isInstanceOf(ConfigException.class).hasMessageContaining("always apply");
        assertThatThrownBy(() -> Settings.load(null, Map.of("mail", "/m", "decision.severity.ENVELOPE",
                "INFO"))).isInstanceOf(ConfigException.class);
    }

    @Test
    void aWeightIsRefusedWhereItWouldHaveNoEffect() throws Exception {
        assertThatThrownBy(() -> Settings.load(null, Map.of("mail", "/m", "decision.weight.ENCODING/LONG_TOKEN", "2")))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("decision.weight.ENCODING/LONG_TOKEN").hasMessageContaining("SCORE");

        final Settings score = Settings.load(null,
                Map.of("mail", "/m", "decision.mode", "SCORE", "decision.weight.ENCODING/LONG_TOKEN", "2"));
        assertThat(score.config().decision().weights()).containsEntry("ENCODING/LONG_TOKEN", 2.0);
    }

    @Test
    void aScoreThresholdIsRefusedWhereItWouldHaveNoEffect() throws Exception {
        assertThatThrownBy(() -> Settings.load(null, Map.of("mail", "/m", "decision.scoreThreshold", "7")))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("decision.scoreThreshold").hasMessageContaining("SCORE");

        final Settings score = Settings.load(null,
                Map.of("mail", "/m", "decision.mode", "SCORE", "decision.scoreThreshold", "7"));
        assertThat(score.config().decision().scoreThreshold()).isEqualTo(7.0);
    }

    @Test
    void withoutDirectoriesThereIsNoStart() {
        assertThatThrownBy(() -> Settings.load(null, Map.of())).isInstanceOf(ConfigException.class)
                .hasMessageContaining("incoming");
    }

}
