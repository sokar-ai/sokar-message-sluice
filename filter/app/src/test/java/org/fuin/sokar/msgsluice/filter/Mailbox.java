package org.fuin.sokar.msgsluice.filter;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.fuin.sokar.msgsluice.filter.detect.ContentDetector;

/**
 * A task's mail directory in a temporary directory, with the filter wired to it: {@code incoming/},
 * {@code sent/}, {@code filter/accepted/} and {@code filter/feedback/} readable as usual, and
 * {@code filter/rejected/} and {@code filter/error/} owner-only, because a refused original still holds
 * in clear text whatever it was refused for.
 */
final class Mailbox {

    final Path root;

    final List<String> log = new ArrayList<>();

    Mailbox(final Path root) {
        this.root = root;
        try {
            for (final String dir : List.of("incoming", "sent", "filter/accepted", "filter/feedback")) {
                Files.createDirectories(root.resolve(dir));
            }
            for (final String dir : List.of("filter/rejected", "filter/error")) {
                Files.createDirectories(root.resolve(dir), PosixFilePermissions.asFileAttribute(
                        PosixFilePermissions.fromString("rwx------")));
            }
        } catch (final IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    Path incoming() {
        return root.resolve("incoming");
    }

    Path accepted() {
        return root.resolve("filter/accepted");
    }

    Path feedback() {
        return root.resolve("filter/feedback");
    }

    Path rejected() {
        return root.resolve("filter/rejected");
    }

    Path error() {
        return root.resolve("filter/error");
    }

    Path deliver(final String name, final String json) {
        try {
            final Path file = incoming().resolve(name);
            Files.writeString(file, json, StandardCharsets.UTF_8);
            return file;
        } catch (final IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    Settings settings(final String... keyValues) throws ConfigException {
        final Map<String, String> cli = new HashMap<>();
        cli.put("mail", root.toString());
        cli.put("stabilityDelayMillis", "0");
        for (int i = 0; i < keyValues.length; i += 2) {
            cli.put(keyValues[i], keyValues[i + 1]);
        }
        return Settings.load(null, cli);
    }

    MessageSluice sluice(final String... keyValues) throws ConfigException {
        final Settings settings = settings(keyValues);
        return new MessageSluice(settings.config(), settings.detectors(), clock(), log::add);
    }

    MessageSluice sluice(final List<ContentDetector> detectors, final String... keyValues) throws ConfigException {
        return new MessageSluice(settings(keyValues).config(), detectors, clock(), log::add);
    }

    static Clock clock() {
        return Clock.fixed(Instant.parse("2026-09-18T06:00:00Z"), ZoneOffset.UTC);
    }

    List<Path> files(final Path dir) {
        try (Stream<Path> s = Files.list(dir)) {
            return s.sorted().toList();
        } catch (final IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    /** Everything the filter wrote or moved anywhere but the refused originals, plus its log, as one string. */
    String everythingThatLeaves() {
        final StringBuilder sb = new StringBuilder(String.join("\n", log));
        try (Stream<Path> s = Files.walk(root)) {
            for (final Path p : s.toList()) {
                sb.append('\n').append(p.getFileName());
                if (Files.isRegularFile(p) && !p.startsWith(rejected()) && !p.startsWith(error())
                        && !p.startsWith(incoming()) && !p.startsWith(accepted())) {
                    sb.append('\n').append(Files.readString(p, StandardCharsets.UTF_8));
                }
            }
        } catch (final IOException ex) {
            throw new UncheckedIOException(ex);
        }
        return sb.toString();
    }

    static String message(final String text) {
        return """
                {"messageId":"msg-7f6c8f6e-7f2e-4d5f-bf8c-1f3c50a29f12","role":"ROLE_AGENT","contextId":"ctx-1",
                 "parts":[{"text":%s,"mediaType":"text/plain"}]}""".formatted(quote(text));
    }

    static String quote(final String text) {
        return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }

}
