package org.fuin.sokar.msgsluice.filter.detect;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;
import java.util.HexFormat;
import java.util.Random;

import org.junit.jupiter.api.Test;

/** A URL is masked only while it looks like one: a host DNS could hold, and a path of ordinary length. */
class MaskedTest {

    static String hex(final int bytes, final long seed) {
        final byte[] b = new byte[bytes];
        new Random(seed).nextBytes(b);
        return HexFormat.of().formatHex(b);
    }

    @Test
    void anOrdinaryUrlIsMaskedAndTheProseAroundItPasses() {
        final String text = "The design is at https://github.com/fuinorg/sokar-message-sluice/blob/main/doc/filter.md"
                + " and the build at http://ci.example.org:8080/job/sluice/42/console, the docs at "
                + "https://sokar-message-sluice.docs.example.org/filter, as discussed.";

        assertThat(Masked.of(text).text()).doesNotContain("github").doesNotContain("console");
        assertThat(EncodedPayloadRatesTest.judge(text).accepted()).isTrue();
    }

    @Test
    void aHostNoDnsNameCouldBeIsNotMasked() {
        final String longHost = "https://" + hex(1500, 1);
        final String validButHex = "https://" + hex(31, 5) + "a." + hex(31, 6) + "b." + hex(31, 7) + "c.org/";
        final String longLabel = "https://" + hex(40, 2) + ".example.org/";
        final String badAlphabet = "https://" + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(hex(24, 3).getBytes(java.nio.charset.StandardCharsets.UTF_8)).replace('-', '_')
                + ".example.org/";

        for (final String url : new String[] {longHost, longLabel, badAlphabet, validButHex}) {
            final String label = url.substring(0, 20);
            assertThat(Masked.of("See " + url + " now.").text()).as(label).contains(url.substring(8, 40));
            assertThat(EncodedPayloadRatesTest.judge("See " + url + " now.").accepted()).as(label).isFalse();
        }
    }

    @Test
    void aPathLongerThanAnyOrdinaryUrlIsNotMasked() {
        final StringBuilder url = new StringBuilder("https://example.org");
        final Random random = new Random(4);
        for (int i = 0; i < 60; i++) {
            final byte[] b = new byte[30];
            random.nextBytes(b);
            url.append('/').append(Base64.getUrlEncoder().withoutPadding().encodeToString(b));
        }

        assertThat(Masked.of("See " + url + " now.").text()).doesNotContain("example.org")
                .contains(url.substring(20, 60));
        assertThat(EncodedPayloadRatesTest.judge("See " + url + " now.").accepted()).isFalse();
    }

}
