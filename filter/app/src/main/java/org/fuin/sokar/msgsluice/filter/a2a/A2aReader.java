package org.fuin.sokar.msgsluice.filter.a2a;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jspecify.annotations.Nullable;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;

/**
 * Parses a file into a JSON tree, strictly. A lenient parser is a bypass: whatever it silently drops or
 * resolves differently from the next reader is where a smuggled field lives.
 */
public final class A2aReader {

    /** Deep enough for any real message, shallow enough that no walk over the tree can overflow the stack. */
    static final int MAX_NESTING = 64;

    private static final Pattern RECOVERABLE_ID = Pattern
            .compile("\"messageId\"\\s*:\\s*\"([A-Za-z0-9._:-]{1,128})\"");

    private final ObjectMapper mapper;

    public A2aReader() {
        final JsonMapper jsonMapper = JsonMapper.builder()
                // {"text":"a","text":"b"} is read as "b" by one parser and "a" by another.
                .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .disable(JsonReadFeature.ALLOW_JAVA_COMMENTS)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
                .enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS)
                .build();
        jsonMapper.getFactory().setStreamReadConstraints(
                StreamReadConstraints.builder().maxNestingDepth(MAX_NESTING).build());
        this.mapper = jsonMapper;
    }

    /** The mapper answers are written with, so that they read back through exactly this reader. */
    public ObjectMapper mapper() {
        return mapper;
    }

    public JsonNode parse(final byte[] bytes) throws Unprocessable {
        if (bytes.length == 0) {
            throw new Unprocessable("UNPROCESSABLE/EMPTY_FILE", "The file is empty.");
        }
        final String text = strictUtf8(bytes);
        try {
            final JsonNode node = mapper.readTree(text);
            if (node == null || node.isMissingNode()) {
                throw new Unprocessable("UNPROCESSABLE/EMPTY_FILE", "The file holds no JSON value.");
            }
            return node;
        } catch (final JsonProcessingException ex) {
            // Some parser messages quote the offending input, so only the position is kept.
            final var location = ex.getLocation();
            final String where = location == null ? ""
                    : " at line " + location.getLineNr() + ", column " + location.getColumnNr();
            throw new Unprocessable("UNPROCESSABLE/MALFORMED_JSON", "The file is not valid JSON" + where + ".");
        }
    }

    /**
     * The file as UTF-8, decoded strictly. JSON between systems is UTF-8 (RFC 8259), and a parser that guesses
     * UTF-16 or UTF-32, skips a byte-order mark or accepts an overlong sequence reads another text than a strict
     * receiver does - the difference is where a smuggled field lives.
     */
    private static String strictUtf8(final byte[] bytes) throws Unprocessable {
        if (bytes.length >= 3 && (bytes[0] & 0xff) == 0xEF && (bytes[1] & 0xff) == 0xBB && (bytes[2] & 0xff) == 0xBF) {
            throw notUtf8();
        }
        for (final byte b : bytes) {
            // Valid UTF-8, but never in JSON text: how UTF-16 and UTF-32 show when read as UTF-8.
            if (b == 0) {
                throw notUtf8();
            }
        }
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch (final CharacterCodingException ex) {
            throw notUtf8();
        }
    }

    private static Unprocessable notUtf8() {
        return new Unprocessable("UNPROCESSABLE/NOT_UTF8",
                "The file is not UTF-8 text without a byte-order mark, which is the only encoding read.");
    }

    /**
     * A message id from a file that could not be parsed, accepted only if it has a plausible shape. Used to tie a
     * rejection to its message; marked as recovered wherever it appears.
     */
    public static @Nullable String recoverMessageId(final byte[] bytes) {
        final Matcher m = RECOVERABLE_ID.matcher(new String(bytes, StandardCharsets.UTF_8));
        return m.find() ? m.group(1) : null;
    }

}
