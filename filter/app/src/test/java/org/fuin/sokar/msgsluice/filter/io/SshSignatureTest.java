package org.fuin.sokar.msgsluice.filter.io;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.Test;

/** The one signature Sokar writes, and everything that only looks like it. */
class SshSignatureTest {

    private static byte[] real() throws IOException {
        try (InputStream in = SshSignatureTest.class.getResourceAsStream("/signatures/sokar-ed25519.sig")) {
            return in.readAllBytes();
        }
    }

    private static byte[] blob(final byte[] armored) {
        final String[] lines = new String(armored, StandardCharsets.US_ASCII).split("\n");
        return Base64.getDecoder().decode(String.join("", Arrays.copyOfRange(lines, 1, lines.length - 1)));
    }

    private static byte[] armor(final byte[] blob) {
        final String b64 = Base64.getEncoder().encodeToString(blob);
        final StringBuilder out = new StringBuilder("-----BEGIN SSH SIGNATURE-----\n");
        for (int i = 0; i < b64.length(); i += 70) {
            out.append(b64, i, Math.min(b64.length(), i + 70)).append('\n');
        }
        return out.append("-----END SSH SIGNATURE-----\n").toString().getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] replace(final byte[] bytes, final String from, final String to) {
        final String s = new String(bytes, StandardCharsets.ISO_8859_1);
        assertThat(s).contains(from);
        return s.replace(from, to).getBytes(StandardCharsets.ISO_8859_1);
    }

    @Test
    void theSignatureSokarWritesIsOne() throws Exception {
        assertThat(real()).hasSize(306);
        assertThat(SshSignature.isSokars(real())).isTrue();
        assertThat(SshSignature.isSokars(armor(blob(real())))).isTrue();
    }

    @Test
    void anythingBesideTheArmorIsRefused() throws Exception {
        final String text = new String(real(), StandardCharsets.US_ASCII);

        assertThat(SshSignature.isSokars((text + "hidden").getBytes(StandardCharsets.US_ASCII))).isFalse();
        assertThat(SshSignature.isSokars((text + "\n").getBytes(StandardCharsets.US_ASCII))).isFalse();
        assertThat(SshSignature.isSokars(("x" + text).getBytes(StandardCharsets.US_ASCII))).isFalse();
        assertThat(SshSignature.isSokars(text.replace("\n", "\r\n").getBytes(StandardCharsets.US_ASCII))).isFalse();
    }

    @Test
    void whatIsNotArmoredOrWrappedAsOpenSshWrapsItIsRefused() throws Exception {
        final String b64 = Base64.getEncoder().encodeToString(blob(real()));

        assertThat(SshSignature.isSokars(new byte[0])).isFalse();
        assertThat(SshSignature.isSokars(b64.getBytes(StandardCharsets.US_ASCII))).isFalse();
        assertThat(SshSignature.isSokars(("-----BEGIN SSH SIGNATURE-----\n" + b64 + "\n-----END SSH SIGNATURE-----\n")
                .getBytes(StandardCharsets.US_ASCII))).isFalse();
        assertThat(SshSignature.isSokars("x".repeat(306).getBytes(StandardCharsets.US_ASCII))).isFalse();
    }

    @Test
    void aBlobOtherThanAnEd25519SignatureInSokarsNamespaceIsRefused() throws Exception {
        final byte[] blob = blob(real());

        assertThat(SshSignature.isSokars(armor(replace(blob, "SSHSIG", "SSHSIH")))).isFalse();
        assertThat(SshSignature.isSokars(armor(replace(blob, "sokar-message", "sokar-massage")))).isFalse();
        assertThat(SshSignature.isSokars(armor(replace(blob, "sha512", "sha256")))).isFalse();
        assertThat(SshSignature.isSokars(armor(replace(blob, "ssh-ed25519", "ssh-ed25518")))).isFalse();
        final byte[] longer = Arrays.copyOf(blob, blob.length + 3);
        assertThat(SshSignature.isSokars(armor(longer))).isFalse();
        assertThat(SshSignature.isSokars(armor(Arrays.copyOf(blob, blob.length - 1)))).isFalse();
    }

    @Test
    void theLimitIsOneKibibyteEverywhere() {
        // doc/filter.md names the value, for whatever carries a signature beside a message.
        assertThat(SshSignature.MAX_BYTES).isEqualTo(1024);
    }

}
