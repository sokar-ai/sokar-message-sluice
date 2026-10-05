package org.fuin.sokar.msgsluice.filter.io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

import org.jspecify.annotations.Nullable;

/**
 * Every write is atomic: a reader of any directory this tool writes into sees a whole file or none.
 */
public final class FileOps {

    /** A signature travels beside its message under the message's name plus this. */
    public static final String SIGNATURE_SUFFIX = ".sig";

    private FileOps() {
    }

    /**
     * Writes {@code bytes} as {@code name} into {@code dir}, through a temporary file in the same directory and a
     * rename. A name that exists already gets a {@code -1}, {@code -2} suffix rather than being overwritten.
     *
     * @return the file written
     */
    public static Path writeAtomically(final Path dir, final String name, final byte[] bytes) throws IOException {
        return writeNew(dir, freeName(dir, name, false), bytes);
    }

    /**
     * A name for a temporary file beside {@code name}: hidden, so no reader of the directory picks it up, and
     * unpredictable, because whoever can write the directory could otherwise plant a link at it in advance. It is
     * always opened with {@code CREATE_NEW}, which neither follows nor reuses what is there.
     */
    static Path temporary(final Path dir, final String name) {
        return dir.resolve("." + name + "." + UUID.randomUUID() + ".tmp");
    }

    /**
     * How a file looks at one moment, read without following a link. Two stamps that are equal mean the same
     * inode, not written to in between: every write changes the change time.
     *
     * @param regularFile whether it is a regular file rather than a link, a directory or a special file
     * @param directory   whether it is a directory
     * @param links       how many names the inode has
     * @param device      the device it lies on
     * @param inode       its inode
     * @param size        its size in bytes
     * @param modified    when its content was last written
     * @param changed     when its content or its inode was last changed
     */
    public record Stamp(boolean regularFile, boolean directory, int links, Object device, Object inode, long size,
            FileTime modified, FileTime changed) {

        /** A regular file with one name: the only kind whose content is what its name shows. */
        public boolean plain() {
            return regularFile && links == 1;
        }

    }

    /**
     * The stamp of {@code file}, or {@code null} if it is gone. Where the filesystem cannot say how many names a
     * file has, this throws rather than guess.
     */
    public static @Nullable Stamp stamp(final Path file) throws IOException {
        final Map<String, Object> a;
        try {
            a = Files.readAttributes(file, "unix:*", LinkOption.NOFOLLOW_LINKS);
        } catch (final NoSuchFileException ex) {
            return null;
        }
        return new Stamp(attribute(a, "isRegularFile", Boolean.class), attribute(a, "isDirectory", Boolean.class),
                attribute(a, "nlink", Integer.class), attribute(a, "dev", Object.class),
                attribute(a, "ino", Object.class), attribute(a, "size", Long.class),
                attribute(a, "lastModifiedTime", FileTime.class), attribute(a, "ctime", FileTime.class));
    }

    /** An attribute the filesystem did not supply is a stamp it cannot give, never a default. */
    private static <T> T attribute(final Map<String, Object> attributes, final String name, final Class<T> type)
            throws IOException {
        final Object value = attributes.get(name);
        if (value == null) {
            throw new IOException("The filesystem does not report '" + name + "'");
        }
        return type.cast(value);
    }

    /**
     * What was read of a file.
     *
     * @param bytes  its content, or {@code null} when it had more than the most that is kept
     * @param size   how many bytes were read, all of them counted even where not kept
     * @param sha256 the hash of all of them
     */
    public record Content(byte @Nullable [] bytes, long size, String sha256) {
    }

    /**
     * Reads a file through one channel opened without following a link, keeping at most {@code max} bytes. Its
     * size is not trusted beforehand: a file that grows while it is read is counted, hashed, and not kept.
     */
    public static Content read(final Path file, final long max) throws IOException {
        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (final NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Every Java runtime has SHA-256", ex);
        }
        final ByteArrayOutputStream kept = new ByteArrayOutputStream();
        long total = 0;
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            final ByteBuffer buffer = ByteBuffer.allocate(64 * 1024);
            for (int n = channel.read(buffer); n >= 0; n = channel.read(buffer)) {
                digest.update(buffer.array(), 0, n);
                if (total + n <= max) {
                    kept.write(buffer.array(), 0, n);
                }
                total += n;
                buffer.clear();
            }
        }
        return new Content(total <= max ? kept.toByteArray() : null, total,
                HexFormat.of().formatHex(digest.digest()));
    }

    /**
     * Writes a checked message, and its signature if it has one, into {@code dir} under one name, the signature
     * first, so a message is never there without the signature that belongs to it. What is written is the bytes
     * that were checked, never the file they came from: that file may have been changed since, or be a name for
     * another file's content.
     *
     * @return where the message is now
     */
    public static Path writeWithSignature(final Path dir, final String name, final byte[] message,
            final byte @Nullable [] signature) throws IOException {
        final String target;
        final Path earlierSignature = dir.resolve(name + SIGNATURE_SUFFIX);
        final boolean signatureWentAhead = signature != null
                && !Files.exists(dir.resolve(name), LinkOption.NOFOLLOW_LINKS)
                && Files.isRegularFile(earlierSignature, LinkOption.NOFOLLOW_LINKS)
                && Arrays.equals(Files.readAllBytes(earlierSignature), signature);
        if (signatureWentAhead) {
            // A crash between the two writes of an earlier run.
            target = name;
        } else {
            target = freeName(dir, name, true);
            if (signature != null) {
                writeNew(dir, target + SIGNATURE_SUFFIX, signature);
            }
        }
        return writeNew(dir, target, message);
    }

    private static Path writeNew(final Path dir, final String name, final byte[] bytes) throws IOException {
        final Path tmp = temporary(dir, name);
        try {
            try (FileChannel channel = FileChannel.open(tmp, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE)) {
                final ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            final Path target = dir.resolve(name);
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                throw new FileAlreadyExistsException(target.toString());
            }
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE);
            return target;
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    /**
     * Deletes {@code file} if it still has the stamp it had when it was read. A file changed since was not what was
     * checked, so it stays for the next pass rather than being dropped.
     *
     * @return whether it was deleted
     */
    public static boolean deleteIfUnchanged(final Path file, final Stamp read) throws IOException {
        if (!read.equals(stamp(file))) {
            return false;
        }
        Files.delete(file);
        return true;
    }

    /**
     * Keeps in {@code dir} the bytes that were read of {@code file}, never the file itself, which may have been
     * changed or replaced by a link since. The original and its signature go only if it still has the stamp it
     * had when it was read; changed, it stays for the next pass.
     *
     * @return where the kept bytes are
     */
    public static Path keepAsRead(final Path file, final Stamp read, final byte[] bytes, final Path dir,
            final String name) throws IOException {
        final Path kept = writeWithSignature(dir, name, bytes, null);
        if (deleteIfUnchanged(file, read)) {
            final Path signature = file.resolveSibling(file.getFileName() + SIGNATURE_SUFFIX);
            if (Files.exists(signature, LinkOption.NOFOLLOW_LINKS)) {
                move(signature, kept.resolveSibling(kept.getFileName() + SIGNATURE_SUFFIX));
            }
        }
        return kept;
    }

    /** {@link #moveWithSignature(Path, Path, String)} under the message's own name. */
    public static Path moveWithSignature(final Path message, final Path dir) throws IOException {
        return moveWithSignature(message, dir, message.getFileName().toString());
    }

    /**
     * Moves a message and, if there is one, its signature into {@code dir}, keeping them paired under
     * {@code name}. The signature goes first, so a message is never in {@code dir} without the signature that
     * belongs to it. A link is moved as a link, never followed.
     *
     * @return where the message is now
     */
    public static Path moveWithSignature(final Path message, final Path dir, final String name) throws IOException {
        final Path signature = message.resolveSibling(message.getFileName() + SIGNATURE_SUFFIX);
        final boolean hasSignature = Files.exists(signature, LinkOption.NOFOLLOW_LINKS);
        final String target;
        if (!hasSignature && Files.exists(dir.resolve(name + SIGNATURE_SUFFIX), LinkOption.NOFOLLOW_LINKS)
                && !Files.exists(dir.resolve(name), LinkOption.NOFOLLOW_LINKS)) {
            // A crash between the two moves of an earlier run: the signature already went ahead.
            target = name;
        } else {
            target = freeName(dir, name, true);
        }
        if (hasSignature) {
            move(signature, dir.resolve(target + SIGNATURE_SUFFIX));
        }
        final Path moved = dir.resolve(target);
        move(message, moved);
        return moved;
    }

    /**
     * An atomic rename, or - where the two directories lie on different filesystems - a copy into a temporary
     * file beside the target and a rename, so the target still only ever appears whole.
     */
    public static void move(final Path source, final Path target) throws IOException {
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            // A rename would silently replace it.
            throw new FileAlreadyExistsException(target.toString());
        }
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (final AtomicMoveNotSupportedException ex) {
            final Path dir = target.toAbsolutePath().getParent();
            if (dir == null) {
                throw new IOException("No directory holds " + target);
            }
            final Path tmp = temporary(dir, target.getFileName().toString());
            try {
                // A link is copied as a link, never through it; the copy refuses a name that is taken.
                Files.copy(source, tmp, StandardCopyOption.COPY_ATTRIBUTES, LinkOption.NOFOLLOW_LINKS);
                if (Files.isRegularFile(tmp, LinkOption.NOFOLLOW_LINKS)) {
                    try (FileChannel channel = FileChannel.open(tmp, StandardOpenOption.WRITE,
                            LinkOption.NOFOLLOW_LINKS)) {
                        channel.force(true);
                    }
                }
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE);
            } finally {
                Files.deleteIfExists(tmp);
            }
            Files.delete(source);
        }
    }

    /** {@code name}, or the first of {@code name-1}, {@code name-2} ... that is free, the extension kept. */
    static String freeName(final Path dir, final String name, final boolean withSignature) {
        final int dot = name.lastIndexOf('.');
        final String base = dot > 0 ? name.substring(0, dot) : name;
        final String ext = dot > 0 ? name.substring(dot) : "";
        String candidate = name;
        for (int i = 1; taken(dir, candidate, withSignature); i++) {
            candidate = base + "-" + i + ext;
        }
        return candidate;
    }

    private static boolean taken(final Path dir, final String name, final boolean withSignature) {
        // A dangling link takes a name as much as a file does.
        return Files.exists(dir.resolve(name), LinkOption.NOFOLLOW_LINKS) || withSignature
                && Files.exists(dir.resolve(name + SIGNATURE_SUFFIX), LinkOption.NOFOLLOW_LINKS);
    }

}
