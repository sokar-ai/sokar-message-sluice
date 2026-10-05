package org.fuin.sokar.msgsluice.filter.io;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * One instance at a time. The lock is the operating system's, so it dies with the process and a crashed
 * run never leaves a stale lock behind; the file only says who holds it.
 */
public final class DirectoryLock implements AutoCloseable {

    /** More than a pid line needs; a holder file is never read further than this. */
    private static final int MAX_HOLDER_BYTES = 64;

    private final FileChannel channel;

    private final FileLock lock;

    private DirectoryLock(final FileChannel channel, final FileLock lock) {
        this.channel = channel;
        this.lock = lock;
    }

    /**
     * @throws LockedException when another instance holds it
     */
    public static DirectoryLock acquire(final Path file) throws IOException, LockedException {
        // A link planted at the lock's name would otherwise have its target overwritten with our pid.
        final FileChannel channel = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.READ,
                StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
        try {
            FileLock lock;
            try {
                lock = channel.tryLock();
            } catch (final OverlappingFileLockException ex) {
                // Held by this very process: another instance all the same.
                lock = null;
            }
            if (lock == null) {
                final String holder = holder(channel);
                throw new LockedException("Another instance holds " + file
                        + (holder.isEmpty() ? "" : " (" + holder + ")"));
            }
            try {
                channel.truncate(0);
                channel.write(ByteBuffer.wrap(("pid " + ProcessHandle.current().pid())
                        .getBytes(StandardCharsets.UTF_8)), 0);
                channel.force(true);
            } catch (final IOException | RuntimeException ex) {
                lock.release();
                throw ex;
            }
            return new DirectoryLock(channel, lock);
        } catch (final IOException | RuntimeException | LockedException ex) {
            channel.close();
            throw ex;
        }
    }

    /**
     * Who holds it, for the message: read through the channel already open rather than by name again, and reduced
     * to printable ASCII, because anybody who can write the directory can write this file.
     */
    private static String holder(final FileChannel channel) throws IOException {
        final ByteBuffer buffer = ByteBuffer.allocate(MAX_HOLDER_BYTES);
        channel.read(buffer, 0);
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < buffer.position(); i++) {
            final byte b = buffer.get(i);
            sb.append(b >= 0x20 && b < 0x7f ? (char) b : '?');
        }
        return sb.toString().strip();
    }

    @Override
    public void close() throws IOException {
        try {
            lock.release();
        } finally {
            channel.close();
        }
    }

    /** Another instance is running. */
    public static final class LockedException extends Exception {

        private static final long serialVersionUID = 1L;

        public LockedException(final String message) {
            super(message);
        }

    }

}
