package org.fuin.sokar.msgsluice.filter.io;

import java.io.CharConversionException;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.jspecify.annotations.Nullable;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;

/**
 * The message ids already processed: whatever sits in the directories an accepted or refused message ends
 * up in. Read from the files every time it is built, so it is never a second source of truth that could
 * disagree with the directories.
 */
public final class MessageArchive {

    private final Set<String> ids = new HashSet<>();

    private MessageArchive() {
    }

    /**
     * Collects the ids of every {@code *.json} in the given directories. A file that is no message counts for
     * nothing; a file or a directory that cannot be read stops the scan, because an id missing from it would let
     * its duplicate through.
     *
     * <p>
     * Only what the filter itself files counts: a plain file with one name, of at most {@code maxBytes}. A link, a
     * second name for another file or a special file is never opened - it could point outside the mailbox, block
     * the read, or plant an id that refuses a message that never came before - and a larger file is not read.
     */
    public static MessageArchive scan(final List<Path> dirs, final long maxBytes) throws IOException {
        final MessageArchive archive = new MessageArchive();
        final JsonFactory factory = new JsonFactory();
        for (final Path dir : dirs) {
            try (DirectoryStream<Path> files = Files.newDirectoryStream(dir, "*.json")) {
                for (final Path file : files) {
                    final String id = topLevelMessageId(factory, dir, file, maxBytes);
                    if (id != null) {
                        archive.ids.add(id);
                    }
                }
            }
        }
        return archive;
    }

    public boolean contains(final String messageId) {
        return ids.contains(messageId);
    }

    public void add(final String messageId) {
        ids.add(messageId);
    }

    /** Reads only the top-level {@code messageId}, of a file no larger than a message may be. */
    private static @Nullable String topLevelMessageId(final JsonFactory factory, final Path dir, final Path file,
            final long maxBytes) throws IOException {
        final byte[] bytes;
        try {
            final FileOps.Stamp stamp = FileOps.stamp(file);
            if (stamp == null || !stamp.plain() || stamp.size() > maxBytes) {
                return null;
            }
            bytes = FileOps.read(file, maxBytes).bytes();
        } catch (final IOException ex) {
            // Not the file's name: a refused original's name may be what it was refused for.
            throw new IOException("A message in " + dir + " cannot be read: " + ex.getClass().getSimpleName());
        }
        if (bytes == null) {
            return null;
        }
        try (JsonParser parser = factory.createParser(bytes)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                return null;
            }
            while (parser.nextToken() == JsonToken.FIELD_NAME) {
                final String name = parser.currentName();
                final JsonToken value = parser.nextToken();
                if ("messageId".equals(name) && value == JsonToken.VALUE_STRING) {
                    return parser.getText();
                }
                parser.skipChildren();
            }
            return null;
        } catch (final JsonProcessingException | CharConversionException | RuntimeException ex) {
            // Not a message, so it holds no id.
            return null;
        }
    }

}
