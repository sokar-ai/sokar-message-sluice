package org.fuin.sokar.msgsluice.filter.io;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A queue need not lie on the mailbox's filesystem, and then a rename is impossible: the move copies into a
 * temporary file beside the target and renames that. Run between {@code /dev/shm} and this module's
 * {@code target/}, which are different filesystems on a usual Linux machine and on CI; skipped, and saying so,
 * where they are not.
 */
class CrossFilesystemTest {

    private Path source;

    private Path target;

    @BeforeEach
    void twoFilesystems() throws Exception {
        final Path shm = Path.of("/dev/shm");
        Assumptions.assumeTrue(Files.isDirectory(shm) && Files.isWritable(shm), "no writable /dev/shm here");
        source = Files.createTempDirectory(shm, "sluice-cross-");
        target = Files.createTempDirectory(Files.createDirectories(Path.of("target")).toAbsolutePath(),
                "sluice-cross-");
        Assumptions.assumeFalse(Files.getFileStore(source).equals(Files.getFileStore(target)),
                "/dev/shm and target/ are one filesystem here, so this test proves nothing");
    }

    @AfterEach
    void cleanUp() throws Exception {
        for (final Path dir : new Path[] {source, target}) {
            if (dir != null && Files.exists(dir)) {
                try (Stream<Path> files = Files.walk(dir)) {
                    for (final Path p : files.sorted(java.util.Comparator.reverseOrder()).toList()) {
                        Files.delete(p);
                    }
                }
            }
        }
    }

    @Test
    void aMessageAndItsSignatureCrossIntactAndNothingIsLeftBehind() throws Exception {
        final byte[] bytes = "{\"messageId\":\"m-1\",\"role\":\"ROLE_AGENT\",\"parts\":[{\"text\":\"Hi.\"}]}"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        final Path message = Files.write(source.resolve("m-1.json"), bytes);
        Files.writeString(source.resolve("m-1.json.sig"), "signature");
        // The premise: a rename between these two directories is refused, so the fallback is what runs.
        final Path probe = Files.writeString(source.resolve("probe"), "x");
        assertThatThrownBy(() -> Files.move(probe, target.resolve("probe"), StandardCopyOption.ATOMIC_MOVE))
                .isInstanceOf(AtomicMoveNotSupportedException.class);

        final Path moved = FileOps.moveWithSignature(message, target);

        assertThat(Files.readAllBytes(moved)).isEqualTo(bytes);
        assertThat(target.resolve("m-1.json.sig")).hasContent("signature");
        assertThat(message).doesNotExist();
        assertThat(source.resolve("m-1.json.sig")).doesNotExist();
        try (Stream<Path> left = Files.list(target)) {
            assertThat(left.map(p -> p.getFileName().toString())).containsExactlyInAnyOrder("m-1.json",
                    "m-1.json.sig");
        }
    }

    @Test
    void anExistingTargetIsNotOverwrittenAcrossFilesystemsEither() throws Exception {
        final Path message = Files.writeString(source.resolve("m-1.json"), "new");
        Files.writeString(target.resolve("m-1.json"), "old");

        assertThatThrownBy(() -> FileOps.move(message, target.resolve("m-1.json")))
                .isInstanceOf(java.nio.file.FileAlreadyExistsException.class);
        assertThat(target.resolve("m-1.json")).hasContent("old");
        assertThat(message).exists();
    }

}
