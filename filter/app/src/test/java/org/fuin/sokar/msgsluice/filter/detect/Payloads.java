package org.fuin.sokar.msgsluice.filter.detect;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;

/** Generators for the detectors' negative samples: random bytes in each encoding, cut to a given length. */
final class Payloads {

    private Payloads() {
    }

    static Map<String, Function<Random, String>> generators(final int length) {
        final Map<String, Function<Random, String>> g = new LinkedHashMap<>();
        g.put("base64", r -> cut(Base64.getEncoder().encodeToString(bytes(r, length)), length));
        g.put("base64url", r -> cut(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes(r, length)), length));
        g.put("base32", r -> cut(base32(bytes(r, length)), length));
        g.put("base58", r -> cut(base58(bytes(r, length)), length));
        g.put("base85", r -> cut(ascii85(bytes(r, length)), length));
        g.put("hex", r -> cut(HexFormat.of().formatHex(bytes(r, length)), length));
        g.put("url-encoding", r -> cut(urlEncode(bytes(r, length)), length));
        g.put("quoted-printable", r -> cut(quotedPrintable(bytes(r, length)), length));
        g.put("uuencode", r -> cut(uuencodeLine(bytes(r, 45)), length));
        g.put("pem", r -> "-----BEGIN PRIVATE KEY-----" + cut(Base64.getEncoder().encodeToString(bytes(r, 48)),
                Math.max(0, length - 27)));
        g.put("data-uri", r -> "data:application/octet-stream;base64,"
                + cut(Base64.getEncoder().encodeToString(bytes(r, 48)), Math.max(0, length - 37)));
        g.put("binary", r -> cut(binary(bytes(r, length)), length));
        g.put("ciphertext", r -> cut("U2FsdGVkX1" + Base64.getEncoder().encodeToString(bytes(r, 48)), length));
        return g;
    }

    static byte[] bytes(final Random r, final int n) {
        final byte[] b = new byte[n];
        r.nextBytes(b);
        return b;
    }

    static String cut(final String s, final int n) {
        return s.length() <= n ? s : s.substring(0, n);
    }

    static String base32(final byte[] data) {
        final String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        final StringBuilder sb = new StringBuilder();
        int buffer = 0;
        int bits = 0;
        for (final byte b : data) {
            buffer = buffer << 8 | b & 0xff;
            bits += 8;
            while (bits >= 5) {
                sb.append(alphabet.charAt(buffer >> bits - 5 & 31));
                bits -= 5;
            }
        }
        return sb.toString();
    }

    static String base58(final byte[] data) {
        final String alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        java.math.BigInteger n = new java.math.BigInteger(1, data);
        final StringBuilder sb = new StringBuilder();
        final java.math.BigInteger base = java.math.BigInteger.valueOf(58);
        while (n.signum() > 0) {
            final java.math.BigInteger[] qr = n.divideAndRemainder(base);
            sb.append(alphabet.charAt(qr[1].intValue()));
            n = qr[0];
        }
        return sb.reverse().toString();
    }

    static String ascii85(final byte[] data) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i + 4 <= data.length; i += 4) {
            long v = (data[i] & 0xffL) << 24 | (data[i + 1] & 0xffL) << 16 | (data[i + 2] & 0xffL) << 8
                    | data[i + 3] & 0xffL;
            final char[] c = new char[5];
            for (int k = 4; k >= 0; k--) {
                c[k] = (char) ('!' + v % 85);
                v /= 85;
            }
            sb.append(c);
        }
        return sb.toString();
    }

    static String urlEncode(final byte[] data) {
        return java.net.URLEncoder.encode(new String(data, StandardCharsets.ISO_8859_1), StandardCharsets.ISO_8859_1);
    }

    static String quotedPrintable(final byte[] data) {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : data) {
            final int v = b & 0xff;
            if (v >= 33 && v <= 126 && v != '=') {
                sb.append((char) v);
            } else {
                sb.append('=').append(String.format(Locale.ROOT, "%02X", v));
            }
        }
        return sb.toString();
    }

    static String uuencodeLine(final byte[] data) {
        final StringBuilder sb = new StringBuilder().append((char) (32 + data.length));
        for (int i = 0; i + 3 <= data.length; i += 3) {
            final int v = (data[i] & 0xff) << 16 | (data[i + 1] & 0xff) << 8 | data[i + 2] & 0xff;
            for (int k = 18; k >= 0; k -= 6) {
                final int c = v >> k & 63;
                sb.append(c == 0 ? '`' : (char) (32 + c));
            }
        }
        return sb.toString();
    }

    static String binary(final byte[] data) {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : data) {
            sb.append(String.format("%8s", Integer.toBinaryString(b & 0xff)).replace(' ', '0'));
        }
        return sb.toString();
    }

}
