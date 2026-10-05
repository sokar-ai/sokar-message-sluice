package org.fuin.sokar.msgsluice.filter.io;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import org.jspecify.annotations.Nullable;

/**
 * The one signature Sokar writes beside a message: OpenSSH's SSHSIG, detached, Ed25519, namespace
 * {@code sokar-message}, hash sha512, armored exactly as {@code ssh-keygen -Y sign} writes it.
 *
 * <p>
 * The filter files a signature beside a message it accepts, so a signature it did not read would carry
 * whatever was put into it past every detector. Every field of this shape has a fixed length, so nothing fits
 * beside the key and the signature. Whether the signature is valid is the host's check, not this one.
 */
public final class SshSignature {

    /**
     * What a signature may occupy on disk. Sokar's is 306 bytes, always; the room above that is for nothing, and a
     * new key type would move the limit with it.
     */
    public static final int MAX_BYTES = 1024;

    private static final String BEGIN = "-----BEGIN SSH SIGNATURE-----\n";

    private static final String END = "-----END SSH SIGNATURE-----\n";

    /** Where {@code ssh-keygen} wraps the base64. */
    private static final int LINE = 70;

    private static final byte[] MAGIC = "SSHSIG".getBytes(StandardCharsets.US_ASCII);

    private static final String KEY_TYPE = "ssh-ed25519";

    private static final String NAMESPACE = "sokar-message";

    private static final String HASH = "sha512";

    private static final int ED25519_KEY = 32;

    private static final int ED25519_SIGNATURE = 64;

    private SshSignature() {
    }

    /** Whether these bytes are a signature of the shape Sokar writes, and nothing beside it. */
    public static boolean isSokars(final byte[] bytes) {
        if (bytes.length > MAX_BYTES) {
            return false;
        }
        final String text = new String(bytes, StandardCharsets.US_ASCII);
        // US-ASCII turns every byte above 0x7F into U+FFFD, which the base64 check below refuses.
        if (!text.startsWith(BEGIN) || !text.endsWith(END) || text.length() < BEGIN.length() + END.length()) {
            return false;
        }
        final String body = text.substring(BEGIN.length(), text.length() - END.length());
        final String[] lines = body.split("\n", -1);
        // The body ends in a newline, so split leaves one empty string after the last line.
        if (lines.length < 2 || !lines[lines.length - 1].isEmpty()) {
            return false;
        }
        final StringBuilder base64 = new StringBuilder();
        for (int i = 0; i < lines.length - 1; i++) {
            final String line = lines[i];
            final boolean last = i == lines.length - 2;
            if (line.isEmpty() || line.length() > LINE || (!last && line.length() != LINE)
                    || !line.chars().allMatch(SshSignature::isBase64)) {
                return false;
            }
            base64.append(line);
        }
        final byte[] blob;
        try {
            blob = Base64.getDecoder().decode(base64.toString());
        } catch (final IllegalArgumentException ex) {
            return false;
        }
        // The same bytes encode back to the same text: no padding games, no second encoding of one blob.
        if (!Base64.getEncoder().encodeToString(blob).contentEquals(base64)) {
            return false;
        }
        return isEd25519Sshsig(ByteBuffer.wrap(blob));
    }

    private static boolean isBase64(final int c) {
        return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
                || c == '=';
    }

    private static boolean isEd25519Sshsig(final ByteBuffer in) {
        final byte[] magic = new byte[MAGIC.length];
        if (in.remaining() < magic.length) {
            return false;
        }
        in.get(magic);
        if (!Arrays.equals(magic, MAGIC) || !uint32(in, 1)) {
            return false;
        }
        final ByteBuffer publicKey = string(in);
        if (publicKey == null || !text(publicKey, KEY_TYPE) || !bytes(publicKey, ED25519_KEY)
                || publicKey.hasRemaining()) {
            return false;
        }
        if (!text(in, NAMESPACE) || !bytes(in, 0) || !text(in, HASH)) {
            return false;
        }
        final ByteBuffer signature = string(in);
        return signature != null && text(signature, KEY_TYPE) && bytes(signature, ED25519_SIGNATURE)
                && !signature.hasRemaining() && !in.hasRemaining();
    }

    private static boolean uint32(final ByteBuffer in, final int expected) {
        return in.remaining() >= 4 && in.getInt() == expected;
    }

    /** An SSH string: a big-endian length, then that many bytes. */
    private static @Nullable ByteBuffer string(final ByteBuffer in) {
        if (in.remaining() < 4) {
            return null;
        }
        final int length = in.getInt();
        if (length < 0 || length > in.remaining()) {
            return null;
        }
        final ByteBuffer slice = in.slice(in.position(), length);
        in.position(in.position() + length);
        return slice;
    }

    private static boolean text(final ByteBuffer in, final String expected) {
        final ByteBuffer s = string(in);
        return s != null && s.equals(ByteBuffer.wrap(expected.getBytes(StandardCharsets.US_ASCII)));
    }

    private static boolean bytes(final ByteBuffer in, final int length) {
        final ByteBuffer s = string(in);
        return s != null && s.remaining() == length;
    }

}
