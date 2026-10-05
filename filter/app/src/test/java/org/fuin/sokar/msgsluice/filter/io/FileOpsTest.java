package org.fuin.sokar.msgsluice.filter.io;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileOpsTest {

    @TempDir
    Path tmp;

    @Test
    void aLinkPlantedWhereTheTemporaryFileWouldGoIsNotWrittenThrough() throws Exception {
        final Path dir = Files.createDirectory(tmp.resolve("error"));
        final Path victim = Files.writeString(tmp.resolve("victim.txt"), "precious");
        Files.createSymbolicLink(dir.resolve(".m.json.error.txt.tmp"), victim);

        final Path written = FileOps.writeAtomically(dir, "m.json.error.txt",
                "reason".getBytes(StandardCharsets.UTF_8));

        assertThat(victim).hasContent("precious");
        assertThat(written).hasContent("reason");
        assertThat(Files.isSymbolicLink(written)).isFalse();
    }

    /** Codex's review: an unprocessable file was moved by its path, so a change after the read went along. */
    @Test
    void whatIsKeptIsWhatWasReadAndAChangedOriginalStays() throws Exception {
        final Path incoming = Files.createDirectory(tmp.resolve("incoming"));
        final Path error = Files.createDirectory(tmp.resolve("error"));
        final Path file = Files.writeString(incoming.resolve("m.json"), "not json, as read");
        final FileOps.Stamp read = FileOps.stamp(file);
        final byte[] bytes = Files.readAllBytes(file);
        // Replaced after the read: what the filter must never file as the thing it checked.
        Files.delete(file);
        Files.writeString(incoming.resolve("m.json"), "something never checked");

        final Path kept = FileOps.keepAsRead(file, read, bytes, error, "m.json");

        assertThat(kept).hasContent("not json, as read");
        assertThat(incoming.resolve("m.json")).hasContent("something never checked");
    }

    @Test
    void anUnchangedOriginalGoesWithItsSignature() throws Exception {
        final Path incoming = Files.createDirectory(tmp.resolve("incoming"));
        final Path error = Files.createDirectory(tmp.resolve("error"));
        final Path file = Files.writeString(incoming.resolve("m.json"), "not json");
        Files.writeString(incoming.resolve("m.json.sig"), "sig");

        final Path kept = FileOps.keepAsRead(file, FileOps.stamp(file), Files.readAllBytes(file), error, "m.json");

        assertThat(kept).hasContent("not json");
        assertThat(error.resolve("m.json.sig")).hasContent("sig");
        assertThat(incoming).isEmptyDirectory();
    }

}
