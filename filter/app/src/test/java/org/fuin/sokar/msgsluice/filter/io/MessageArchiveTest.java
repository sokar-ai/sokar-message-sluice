package org.fuin.sokar.msgsluice.filter.io;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MessageArchiveTest {

    private static final long MAX = 1024;

    @TempDir
    Path tmp;

    /**
     * Codex's review: the scan followed links, opened special files and read without a limit. Only a plain file
     * with one name, of at most a message's size, counts now - each of the others would carry an id that is not
     * the filter's.
     */
    @Test
    void onlyAPlainFileOfAMessagesSizeCounts() throws Exception {
        final Path outside = Files.createDirectory(tmp.resolve("outside"));
        final Path mailbox = Files.createDirectory(tmp.resolve("accepted"));
        Files.writeString(outside.resolve("x.json"), "{\"messageId\":\"via-link\"}");
        Files.createSymbolicLink(mailbox.resolve("link.json"), outside.resolve("x.json"));
        Files.writeString(outside.resolve("y.json"), "{\"messageId\":\"via-hard-link\"}");
        Files.createLink(mailbox.resolve("hard.json"), outside.resolve("y.json"));
        Files.writeString(mailbox.resolve("big.json"), "{\"messageId\":\"too-large\",\"x\":\"" + "a".repeat(2000)
                + "\"}");
        Files.writeString(mailbox.resolve("ok.json"), "{\"messageId\":\"plain\"}");
        final Process fifo = new ProcessBuilder("mkfifo", mailbox.resolve("fifo.json").toString()).start();
        assertThat(fifo.waitFor()).isZero();

        final MessageArchive archive = MessageArchive.scan(List.of(mailbox), MAX);

        assertThat(archive.contains("plain")).isTrue();
        assertThat(archive.contains("via-link")).isFalse();
        assertThat(archive.contains("via-hard-link")).isFalse();
        assertThat(archive.contains("too-large")).isFalse();
    }

    @Test
    void theIdsOfEveryMessageAreCollectedAndAFileThatIsNoMessageCountsForNothing() throws Exception {
        Files.writeString(tmp.resolve("a.json"), "{\"role\":\"ROLE_AGENT\",\"messageId\":\"m-1\"}");
        Files.writeString(tmp.resolve("b.json"), "not json");

        final MessageArchive archive = MessageArchive.scan(List.of(tmp), MAX);

        assertThat(archive.contains("m-1")).isTrue();
    }

    @Test
    void aFileThatCannotBeReadStopsTheScanRatherThanLettingItsDuplicateThrough() throws Exception {
        Assumptions.assumeFalse(isRoot(tmp), "root reads a file whatever its permissions");
        final Path file = Files.writeString(tmp.resolve("a.json"), "{\"messageId\":\"m-1\"}");
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("---------"));

        assertThatThrownBy(() -> MessageArchive.scan(List.of(tmp), MAX)).isInstanceOf(IOException.class)
                .hasMessageNotContaining("a.json");
    }

    @Test
    void aMissingDirectoryStopsTheScan() {
        assertThatThrownBy(() -> MessageArchive.scan(List.of(tmp.resolve("gone")), MAX))
                .isInstanceOf(NoSuchFileException.class);
    }

    /** Whether this test runs as root, for whom no permission check proves anything. */
    public static boolean isRoot(final Path dir) throws IOException {
        return Integer.valueOf(0).equals(Files.getAttribute(dir, "unix:uid"));
    }

}
