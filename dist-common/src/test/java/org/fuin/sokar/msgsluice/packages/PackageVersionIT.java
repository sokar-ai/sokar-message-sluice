package org.fuin.sokar.msgsluice.packages;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import org.junit.jupiter.api.Test;

/**
 * The built packages carry the version the build means them to: the {@code .deb}'s {@code Version} and the
 * {@code .rpm}'s version and release, read from the files written, not from the configuration that should have
 * produced them, and held to the project's version as mapped here, not by the build. A plugin that takes its version
 * from a property of the same name somewhere up the parents writes a package the file name does not betray. Read in
 * Java, so the check needs neither {@code dpkg} nor {@code rpm} where it runs. The {@code dist-rpm} module runs it
 * after both packages are written.
 */
class PackageVersionIT {

    /**
     * The version the packages must carry, worked out here from the project's version and the run rather than taken
     * from the property the packaging uses, so a mistake in that mapping is not the answer it is held to: a snapshot
     * becomes {@code ~snapshot.<run>}, which sorts below the release in dpkg and rpm alike; a release stays as it is.
     */
    private static final String VERSION = System.getProperty("sluice.project.version", "")
            .replaceFirst("-SNAPSHOT$", "~snapshot." + System.getProperty("sluice.snapshot.run", ""));

    private static final Path DEB = Path.of(System.getProperty("sluice.deb", ""));

    private static final Path RPM = Path.of(System.getProperty("sluice.rpm", ""));

    private static final int RPM_NAME = 1000;

    private static final int RPM_VERSION = 1001;

    private static final int RPM_RELEASE = 1002;

    @Test
    void theDebCarriesThePackageVersion() throws IOException {
        assertThat(VERSION).as("the version the build maps the project's to").isNotBlank();
        assertThat(DEB).as("the .deb written").isRegularFile();

        final Map<String, String> control = debControl(Files.readAllBytes(DEB));

        assertThat(control.get("Package")).as("the .deb's Package").isEqualTo("sokar-message-sluice-filter");
        assertThat(control.get("Version")).as("the .deb's Version").isEqualTo(VERSION);
    }

    @Test
    void theRpmCarriesThePackageVersionAndReleaseOne() throws IOException {
        assertThat(VERSION).as("the version the build maps the project's to").isNotBlank();
        assertThat(RPM).as("the .rpm written").isRegularFile();

        final Map<Integer, String> header = rpmHeader(Files.readAllBytes(RPM));

        assertThat(header.get(RPM_NAME)).as("the .rpm's name").isEqualTo("sokar-message-sluice-filter");
        assertThat(header.get(RPM_VERSION)).as("the .rpm's version").isEqualTo(VERSION);
        assertThat(header.get(RPM_RELEASE)).as("the .rpm's release").isEqualTo("1");
    }

    /** The fields of the control file in a .deb: an ar archive whose control.tar.gz holds ./control. */
    private static Map<String, String> debControl(final byte[] deb) throws IOException {
        assertThat(new String(deb, 0, 8, StandardCharsets.US_ASCII)).as("the .deb's ar magic").isEqualTo("!<arch>\n");
        int at = 8;
        while (at + 60 <= deb.length) {
            final String name = new String(deb, at, 16, StandardCharsets.US_ASCII).trim();
            final int size = Integer.parseInt(new String(deb, at + 48, 10, StandardCharsets.US_ASCII).trim());
            final int data = at + 60;
            if (name.startsWith("control.tar.gz")) {
                return fields(tarEntry(new GZIPInputStream(new ByteArrayInputStream(deb, data, size)), "control"));
            }
            at = data + size + (size % 2);
        }
        throw new AssertionError("the .deb holds no control.tar.gz");
    }

    private static String tarEntry(final InputStream tar, final String wanted) throws IOException {
        final byte[] block = new byte[512];
        while (tar.readNBytes(block, 0, 512) == 512 && block[0] != 0) {
            final String name = new String(block, 0, 100, StandardCharsets.US_ASCII).replace("\0", "").trim();
            final long size = Long.parseLong(new String(block, 124, 12, StandardCharsets.US_ASCII)
                    .replace("\0", "").trim(), 8);
            final byte[] content = tar.readNBytes((int) size);
            tar.skipNBytes((512 - size % 512) % 512);
            if (name.equals(wanted) || name.equals("./" + wanted)) {
                return new String(content, StandardCharsets.UTF_8);
            }
        }
        throw new AssertionError("the control archive holds no " + wanted);
    }

    private static Map<String, String> fields(final String control) {
        final Map<String, String> fields = new HashMap<>();
        for (final String line : control.split("\n")) {
            final int colon = line.indexOf(':');
            if (colon > 0 && !line.startsWith(" ")) {
                fields.put(line.substring(0, colon), line.substring(colon + 1).trim());
            }
        }
        return fields;
    }

    /**
     * The string tags of an .rpm's main header: after the 96-byte lead comes the signature header, padded to eight
     * bytes, then the header; each is magic, an index of (tag, type, offset, count) and a store.
     */
    private static Map<Integer, String> rpmHeader(final byte[] rpm) {
        final ByteBuffer buffer = ByteBuffer.wrap(rpm);
        assertThat(buffer.getInt(0)).as("the .rpm's lead magic").isEqualTo(0xedabeedb);
        final int signatureEnd = headerEnd(buffer, 96);
        final int header = signatureEnd + (8 - signatureEnd % 8) % 8;
        assertThat(buffer.getInt(header) >>> 8).as("the .rpm's header magic").isEqualTo(0x8eade8);
        final int entries = buffer.getInt(header + 8);
        final int store = header + 16 + entries * 16;
        final Map<Integer, String> strings = new HashMap<>();
        for (int i = 0; i < entries; i++) {
            final int entry = header + 16 + i * 16;
            final int tag = buffer.getInt(entry);
            final int type = buffer.getInt(entry + 4);
            final int offset = buffer.getInt(entry + 8);
            if (type == 6) {
                int end = store + offset;
                while (rpm[end] != 0) {
                    end++;
                }
                strings.put(tag, new String(rpm, store + offset, end - store - offset, StandardCharsets.UTF_8));
            }
        }
        return strings;
    }

    private static int headerEnd(final ByteBuffer buffer, final int start) {
        assertThat(buffer.getInt(start) >>> 8).as("the .rpm's signature magic").isEqualTo(0x8eade8);
        return start + 16 + buffer.getInt(start + 8) * 16 + buffer.getInt(start + 12);
    }

}
