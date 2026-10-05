package org.fuin.sokar.msgsluice.filter.io;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DirectoryLockTest {

    @TempDir
    Path tmp;

    @Test
    void aLockFileThatIsALinkIsRefusedAndWhatItPointsAtIsLeftAlone() throws Exception {
        final Path victim = Files.writeString(tmp.resolve("victim.txt"), "precious");
        final Path lock = Files.createSymbolicLink(tmp.resolve(".lock"), victim);

        assertThatThrownBy(() -> DirectoryLock.acquire(lock)).isInstanceOf(IOException.class);

        assertThat(victim).hasContent("precious");
    }

    @Test
    void aHolderThatIsNotUtf8StillMeansAnotherInstance() throws Exception {
        final Path lock = tmp.resolve(".lock");
        try (DirectoryLock held = DirectoryLock.acquire(lock)) {
            Files.write(lock, new byte[] {(byte) 0xff, (byte) 0xfe, 'x'});

            assertThatThrownBy(() -> DirectoryLock.acquire(lock)).isInstanceOf(DirectoryLock.LockedException.class)
                    .hasMessageContaining("Another instance");
        }
    }

}
