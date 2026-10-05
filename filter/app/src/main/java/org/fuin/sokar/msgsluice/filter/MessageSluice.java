package org.fuin.sokar.msgsluice.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchService;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import org.fuin.sokar.msgsluice.filter.a2a.A2aReader;
import org.fuin.sokar.msgsluice.filter.a2a.EnvelopeCheck;
import org.fuin.sokar.msgsluice.filter.a2a.EnvelopeResult;
import org.fuin.sokar.msgsluice.filter.a2a.MessageFacts;
import org.fuin.sokar.msgsluice.filter.a2a.Unprocessable;
import org.fuin.sokar.msgsluice.filter.decision.DecisionModel;
import org.fuin.sokar.msgsluice.filter.decision.Finding;
import org.fuin.sokar.msgsluice.filter.decision.Redactor;
import org.fuin.sokar.msgsluice.filter.decision.Severity;
import org.fuin.sokar.msgsluice.filter.decision.Verdict;
import org.fuin.sokar.msgsluice.filter.detect.ContentDetector;
import org.fuin.sokar.msgsluice.filter.detect.DetectorRunner;
import org.fuin.sokar.msgsluice.filter.detect.TextUnderCheck;
import org.fuin.sokar.msgsluice.filter.io.FileOps;
import org.fuin.sokar.msgsluice.filter.io.SshSignature;
import org.fuin.sokar.msgsluice.filter.io.MessageArchive;
import org.jspecify.annotations.Nullable;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * The filter: reads every message in {@code incoming/}, judges it, answers, and files it - into
 * {@code accepted/}, {@code rejected/} or {@code error/}. It owns no queue and never learns which transport
 * carries a message.
 *
 * <p>
 * What is filed into {@code accepted/} or {@code rejected/} is written from the bytes that were checked, and the
 * original is deleted only if it is unchanged since: a file in {@code incoming/} can be rewritten, or be a second
 * name for another file, after it was read.
 *
 * <p>
 * Per message the answer is written before the message is filed. A crash in between leaves the message to be
 * processed again - at worst a second answer, never a message silently swallowed. A message that cannot be filed
 * is answered once by this process however often it is tried.
 */
public final class MessageSluice {

    /**
     * How long a message file name may be. The name travels with the message to the peer, so it is kept short and
     * plain; the length leaves room for a transport's {@code <account>--} in front of a timestamp and a UUID.
     */
    static final int MAX_NAME_LENGTH = 128;

    private static final Pattern MESSAGE_FILE_NAME = Pattern
            .compile("[A-Za-z0-9][A-Za-z0-9._-]{0," + (MAX_NAME_LENGTH - 6) + "}\\.json");

    /** An SSH signature of any key type is well under this; more would be a second channel beside the message. */

    static final String FILE_NAME_LOCATION = "fileName";

    /** The SHA-256 of no bytes: what an answer names as the hash of a file that was not read. */
    private static final String NOTHING_READ = Redactor.sha256(new byte[0]);

    private final FilterConfig config;

    private final A2aReader reader = new A2aReader();

    private final EnvelopeCheck envelope;

    private final DetectorRunner detectors;

    private final DecisionModel decisionModel;

    private final Answers answers;

    private final Clock clock;

    private final Consumer<String> log;

    private final Pause pause;

    /** Answers written for a name and its bytes that could not be filed yet, by that key. */
    private final Map<String, String> answered = new HashMap<>();

    /** Each mailbox directory's device and inode when it was checked; a pass refuses to run on another. */
    private final Map<Path, List<Object>> directories = new HashMap<>();

    public MessageSluice(final FilterConfig config, final List<ContentDetector> detectors, final Clock clock,
            final Consumer<String> log) {
        this(config, detectors, clock, log, Thread::sleep);
    }

    MessageSluice(final FilterConfig config, final List<ContentDetector> detectors, final Clock clock,
            final Consumer<String> log, final Pause pause) {
        this.config = Objects.requireNonNull(config, "config");
        this.envelope = new EnvelopeCheck(config.check());
        this.detectors = new DetectorRunner(detectors, new Redactor(config.redaction()));
        this.decisionModel = new DecisionModel(config.decision());
        this.answers = new Answers(reader.mapper(), version(),
                detectors.stream().map(ContentDetector::id).toList());
        this.clock = Objects.requireNonNull(clock, "clock");
        this.log = Objects.requireNonNull(log, "log");
        this.pause = Objects.requireNonNull(pause, "pause");
    }

    /** The version this build carries, or {@code development} when run from classes rather than a jar. */
    public static String version() {
        final String version = MessageSluice.class.getPackage().getImplementationVersion();
        return version == null ? "development" : version;
    }

    /**
     * Every directory must exist and be a directory, not a link to one, and the two that hold clear-text secrets
     * must be readable by their owner only. The filter creates nothing: a directory that is missing means the
     * host set it up wrongly. What each one is - its device and inode - is remembered, and every pass checks it
     * again, so a directory replaced since, or reached through a parent that was, is never written into.
     */
    public void checkDirectories() throws ConfigException {
        for (final Path dir : mailboxDirectories()) {
            if (!Files.isDirectory(dir)) {
                throw new ConfigException("Not a directory: " + dir);
            }
            // A link would read from or file into wherever it points: an accepted message outside the mailbox.
            if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
                throw new ConfigException(dir + " must be a directory, not a link");
            }
        }
        for (final Path dir : List.of(config.rejected(), config.error())) {
            // A link would put the refused originals wherever it points, under whatever permissions are there.
            if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
                throw new ConfigException(dir + " holds refused originals in clear text and must be a directory, "
                        + "not a link");
            }
            final PosixFileAttributeView view = Files.getFileAttributeView(dir, PosixFileAttributeView.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (view == null) {
                // Without permissions nobody can say who may read the refused originals.
                throw new ConfigException(dir + " holds refused originals in clear text, and its filesystem has "
                        + "no POSIX permissions to keep them to their owner");
            }
            try {
                final PosixFileAttributes attributes = view.readAttributes();
                final UserPrincipal me = dir.getFileSystem().getUserPrincipalLookupService()
                        .lookupPrincipalByName(System.getProperty("user.name"));
                if (!attributes.owner().equals(me)) {
                    throw new ConfigException(dir + " holds refused originals in clear text and must be owned by "
                            + "the user the filter runs as");
                }
                final Set<PosixFilePermission> permissions = attributes.permissions();
                final Set<PosixFilePermission> others = EnumSet.of(PosixFilePermission.GROUP_READ,
                        PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_EXECUTE,
                        PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE,
                        PosixFilePermission.OTHERS_EXECUTE);
                others.retainAll(permissions);
                if (!others.isEmpty()) {
                    throw new ConfigException(dir + " holds refused originals in clear text and must be 0700");
                }
            } catch (final IOException ex) {
                throw new ConfigException("Cannot read the owner and permissions of " + dir + ": "
                        + ex.getClass().getSimpleName() + " " + ex.getMessage());
            }
        }
        for (final Path dir : mailboxDirectories()) {
            try {
                directories.put(dir, identity(dir));
            } catch (final IOException | UnsupportedOperationException ex) {
                throw new ConfigException("Cannot read what " + dir + " is, so a replaced one could not be told "
                        + "apart: " + ex.getClass().getSimpleName());
            }
        }
    }

    private List<Path> mailboxDirectories() {
        return List.of(config.incoming(), config.accepted(), config.corpus(), config.feedback(), config.rejected(),
                config.error());
    }

    private static List<Object> identity(final Path dir) throws IOException {
        final FileOps.Stamp stamp = FileOps.stamp(dir);
        if (stamp == null || !stamp.directory()) {
            throw new IOException(dir + " was replaced since the filter checked it, or is gone: it is no longer a "
                    + "directory; nothing is read from or filed into it");
        }
        return List.of(stamp.device(), stamp.inode());
    }

    /** Stops a pass on a mailbox whose directories are not the ones checked at the start. */
    private void sameDirectories() throws IOException {
        for (final Map.Entry<Path, List<Object>> dir : directories.entrySet()) {
            if (!dir.getValue().equals(identity(dir.getKey()))) {
                throw new IOException(dir.getKey() + " was replaced since the filter checked it; nothing is read "
                        + "from or filed into it");
            }
        }
    }

    /** One pass over everything in {@code incoming/}. */
    public RunSummary runOnce() throws IOException {
        sameDirectories();
        final long started = System.nanoTime();
        final List<FileResult> results = new ArrayList<>();
        final MessageArchive archive = MessageArchive.scan(
                List.of(config.accepted(), config.rejected(), config.corpus()), config.check().maxFileSizeBytes());
        for (final Path file : stableFiles(results)) {
            final FileResult result = process(file, archive, false);
            if (result != null) {
                results.add(result);
            }
        }
        return new RunSummary(results, Duration.ofNanos(System.nanoTime() - started));
    }

    /** Checks one file and moves nothing, writes nothing. For diagnosis. */
    public FileResult dryRun(final Path file) throws IOException {
        final FileResult result = process(file, MessageArchive.scan(List.of(), config.check().maxFileSizeBytes()), true);
        if (result == null) {
            throw new NoSuchFileException(file.toString());
        }
        return result;
    }

    /**
     * Runs a pass whenever something arrives, and at least every {@code watchInterval}, until the thread is
     * interrupted. A pass that fails on a directory ends the watch: a filter that silently checks less is
     * indistinguishable from one that works.
     */
    public void watch(final Consumer<RunSummary> each) throws IOException {
        try (WatchService watcher = config.incoming().getFileSystem().newWatchService()) {
            config.incoming().register(watcher, StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_MODIFY);
            while (!Thread.currentThread().isInterrupted()) {
                final RunSummary summary = runOnce();
                if (!summary.results().isEmpty()) {
                    each.accept(summary);
                }
                final var key = watcher.poll(config.watchInterval().toMillis(), TimeUnit.MILLISECONDS);
                if (key != null) {
                    key.pollEvents();
                    key.reset();
                }
            }
        } catch (final InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * The {@code *.json} entries whose size did not change over {@code stabilityDelay}. A file still growing is set
     * aside for the next pass rather than parsed half-written. Dot files and other suffixes are ignored, which is
     * where a deliverer's {@code .tmp} and {@code .part} files are. A link or a special file is kept, so that it is
     * refused rather than silently left lying; a file gone meanwhile is simply gone.
     */
    private List<Path> stableFiles(final List<FileResult> results) throws IOException {
        final Map<Path, Long> sizes = new LinkedHashMap<>();
        try (DirectoryStream<Path> files = Files.newDirectoryStream(config.incoming(), "*.json")) {
            final List<Path> sorted = new ArrayList<>();
            files.forEach(sorted::add);
            sorted.sort(null);
            for (final Path file : sorted) {
                if (file.getFileName().toString().startsWith(".")) {
                    continue;
                }
                final FileOps.Stamp stamp = FileOps.stamp(file);
                if (stamp != null && !stamp.directory()) {
                    sizes.put(file, stamp.size());
                }
            }
        }
        if (sizes.isEmpty() || config.stabilityDelay().isZero()) {
            return List.copyOf(sizes.keySet());
        }
        try {
            pause.pause(config.stabilityDelay());
        } catch (final InterruptedException ex) {
            Thread.currentThread().interrupt();
            return List.of();
        }
        final List<Path> stable = new ArrayList<>();
        for (final Map.Entry<Path, Long> e : sizes.entrySet()) {
            final FileOps.Stamp stamp = FileOps.stamp(e.getKey());
            if (stamp == null) {
                continue;
            }
            if (stamp.size() == e.getValue()) {
                stable.add(e.getKey());
            } else {
                results.add(new FileResult(checkName(e.getKey().getFileName().toString()).display(), Outcome.SET_ASIDE,
                        List.of(), null, "still being written"));
            }
        }
        return stable;
    }

    /** One file, or {@code null} if it was gone before its turn came. */
    private @Nullable FileResult process(final Path file, final MessageArchive archive, final boolean dry) {
        final String name = file.getFileName().toString();
        // Until the name has been checked it is not shown.
        String display = hashedName(name);
        final Instant now = clock.instant();
        try {
            final FileOps.Stamp stamp = FileOps.stamp(file);
            if (stamp == null) {
                return null;
            }
            if (!stamp.plain()) {
                final NameCheck checked = checkName(name);
                display = checked.display();
                // Neither a link's target nor a second name's inode was put here by the host, so neither is read.
                return unprocessable(file, null, checked.kept(), display,
                        new FileOps.Content(new byte[0], 0, NOTHING_READ), null,
                        new Unprocessable("UNPROCESSABLE/NOT_A_PLAIN_FILE", "It is not a plain file. A link, a "
                                + "file with a second name or a special file is not read."),
                        now, dry);
            }
            final FileOps.Content content;
            try {
                content = FileOps.read(file, config.check().maxFileSizeBytes());
            } catch (final NoSuchFileException ex) {
                return null;
            }
            if (!stamp.equals(FileOps.stamp(file))) {
                final FileResult result = new FileResult(display, Outcome.SET_ASIDE, List.of(), null,
                        "changed while being read");
                log.accept(result.describe());
                return result;
            }
            final NameCheck checked = checkName(name);
            display = checked.display();
            if (!checked.plain()) {
                return unprocessable(file, stamp, checked.kept(), display, content, null, new Unprocessable(
                        "UNPROCESSABLE/FILE_NAME", "The file name is not 1 to " + MAX_NAME_LENGTH
                                + " letters, digits, '.', '_' and '-' starting with a letter or digit and ending "
                                + "in .json."),
                        now, dry);
            }

            final Path signaturePath = file.resolveSibling(name + FileOps.SIGNATURE_SUFFIX);
            final FileOps.Stamp signatureStamp = FileOps.stamp(signaturePath);
            byte[] signature = null;
            if (signatureStamp != null) {
                final FileOps.Content read =
                        signatureStamp.plain() && signatureStamp.size() <= SshSignature.MAX_BYTES
                                ? FileOps.read(signaturePath, SshSignature.MAX_BYTES)
                                : null;
                // It is filed beside an accepted message, so it must be a signature and nothing else.
                if (read == null || read.bytes() == null || !signatureStamp.equals(FileOps.stamp(signaturePath))
                        || !SshSignature.isSokars(read.bytes())) {
                    return unprocessable(file, stamp, checked.kept(), display, content, null, new Unprocessable(
                            "UNPROCESSABLE/SIGNATURE_UNUSABLE", "The file beside the message is not a plain file "
                                    + "holding an SSH signature as Sokar writes it."),
                            now, dry);
                }
                signature = read.bytes();
            }

            final byte[] bytes = content.bytes();
            if (bytes == null) {
                return unprocessable(file, stamp, checked.kept(), display, content, null,
                        new Unprocessable("UNPROCESSABLE/FILE_TOO_LARGE", "The file has " + content.size()
                                + " bytes; at most " + config.check().maxFileSizeBytes() + " are read."),
                        now, dry);
            }
            final EnvelopeResult result;
            try {
                final JsonNode root = reader.parse(bytes);
                result = envelope.check(root);
            } catch (final Unprocessable ex) {
                return unprocessable(file, stamp, checked.kept(), display, content, recoverMessageId(bytes), ex, now,
                        dry);
            }

            List<Finding> findings = new ArrayList<>(result.findings());
            final String messageId = result.facts().messageId();
            if (messageId != null && archive.contains(messageId)) {
                findings.add(Finding.envelope("ENVELOPE/DUPLICATE_MESSAGE_ID", Severity.BLOCKING, "messageId", -1,
                        "A message with this id was processed already. A new message needs a new id."));
            }
            findings.addAll(checked.findings());
            // With a blocking envelope finding the verdict stands before a character of text is analyzed.
            final boolean detectorsRun = findings.stream()
                    .noneMatch(f -> f.stage().alwaysRefuses() && f.severity() == Severity.BLOCKING);
            if (detectorsRun) {
                findings.addAll(detectors.run(result.texts()));
            }
            findings = result.withKeysHidden(findings, detectorsRun);
            final Verdict verdict = decisionModel.decide(findings, config.blocking());
            final Answers.Answer answer = answers.verdict(result.echoable(findings), verdict, config.blocking(),
                    now);

            String answerFile = null;
            String note = verdict.accepted() && verdict.wouldReject() ? "reporting: blocking mode would refuse it"
                    : "";
            if (!dry) {
                final String key = name + "\n" + content.sha256();
                // A message blocking would have refused is always answered: the answer is how the host learns it
                // was flagged, and switching receipts off is about clean messages only.
                if (!verdict.accepted() || verdict.wouldReject() || config.receiptOnApproval()) {
                    answerFile = answerOnce(key, answer);
                }
                // What passes, passes as it came, name included; what is refused keeps no name a rule matched.
                FileOps.writeWithSignature(verdict.accepted() ? config.accepted() : config.rejected(),
                        verdict.accepted() ? name : checked.kept(), bytes, signature);
                answered.remove(key);
                if (messageId != null) {
                    archive.add(messageId);
                }
                boolean removed = FileOps.deleteIfUnchanged(file, stamp);
                if (signatureStamp != null) {
                    removed &= FileOps.deleteIfUnchanged(signaturePath, signatureStamp);
                }
                if (!removed) {
                    note = (note.isEmpty() ? "" : note + "; ")
                            + "changed after it was checked, so the original stays for the next pass";
                }
            }
            final FileResult fileResult = new FileResult(display,
                    verdict.accepted() ? Outcome.ACCEPTED : Outcome.REJECTED, verdict.findings(), answerFile, note);
            log.accept(fileResult.describe());
            return fileResult;
        } catch (final IOException | RuntimeException ex) {
            // The exception's message may name a path, never content; still, only its type goes to the log.
            final FileResult fileResult = new FileResult(display, Outcome.ERROR, List.of(), null,
                    "technical error: " + ex.getClass().getSimpleName());
            log.accept(fileResult.describe());
            return fileResult;
        }
    }

    /**
     * A message's file name travels with it, so it is checked like any text in it: it must be plain, and the
     * detectors must find nothing in it before it is repeated anywhere.
     *
     * @param plain    whether it matches the pattern of a message file name
     * @param findings what the detectors found in it
     * @param kept     the name it is kept under when refused
     * @param display  how a log line names it
     */
    private record NameCheck(boolean plain, List<Finding> findings, String kept, String display) {
    }

    private NameCheck checkName(final String name) {
        final boolean plain = MESSAGE_FILE_NAME.matcher(name).matches();
        final List<Finding> findings = plain
                ? detectors.run(List.of(new TextUnderCheck(FILE_NAME_LOCATION, -1, name)))
                : List.of();
        final boolean shown = plain && findings.isEmpty();
        return new NameCheck(plain, findings, shown ? name : hashedName(name),
                shown ? Answers.safeFileName(name) : hashedName(name));
    }

    /**
     * @param stamp    the file's stamp when it was read, or {@code null} for one that was not read at all
     * @param keptName the name it is kept under in {@code error/} and shown under in the answer: its own, unless
     *                 that is what must not be repeated
     */
    private FileResult unprocessable(final Path file, final FileOps.@Nullable Stamp stamp, final String keptName,
            final String display, final FileOps.Content content, final @Nullable String recoveredId,
            final Unprocessable ex, final Instant now, final boolean dry) throws IOException {
        final Answers.Answer answer = answers.unprocessable(ex.ruleId(), ex.reason(), keptName, content.sha256(),
                content.size(), recoveredId, MessageFacts.NONE, now);
        String answerFile = null;
        if (!dry) {
            final String key = file.getFileName() + "\n" + content.sha256();
            answerFile = answerOnce(key, answer);
            final Path moved = keep(file, stamp, keptName, content);
            answered.remove(key);
            FileOps.writeAtomically(config.error(), moved.getFileName() + ".error.txt",
                    (ex.ruleId() + "\n" + ex.reason() + "\nsha256 " + content.sha256() + "\n")
                            .getBytes(StandardCharsets.UTF_8));
        }
        final FileResult result = new FileResult(display, Outcome.UNPROCESSABLE,
                List.of(Finding.envelope(ex.ruleId(), Severity.BLOCKING, null, -1, ex.reason())), answerFile, "");
        log.accept(result.describe());
        return result;
    }

    /**
     * Keeps a file that is no message in {@code error/}. What was read is kept as it was read - the bytes, never
     * the file they came from, which may have been changed or replaced by a link since - and the original goes only
     * if it is still what was read; changed, it stays for the next pass. A file that was not read - a link, a second
     * name, a special file - or not read whole is moved as it is, a link as a link, never followed.
     */
    private Path keep(final Path file, final FileOps.@Nullable Stamp stamp, final String keptName,
            final FileOps.Content content) throws IOException {
        final byte[] bytes = content.bytes();
        if (stamp == null || bytes == null) {
            return FileOps.moveWithSignature(file, config.error(), keptName);
        }
        return FileOps.keepAsRead(file, stamp, bytes, config.error(), keptName);
    }

    /**
     * Writes an answer unless this process already wrote one for the same name and bytes that is still there. A
     * message that cannot be filed is tried again on every pass, and would otherwise be answered on every pass.
     */
    private String answerOnce(final String key, final Answers.Answer answer) throws IOException {
        final String earlier = answered.get(key);
        if (earlier != null && Files.exists(config.feedback().resolve(earlier), LinkOption.NOFOLLOW_LINKS)) {
            return earlier;
        }
        final String written = write(answer);
        answered.put(key, written);
        return written;
    }

    /** A recovered id is echoed only if no detector finds anything in it: it could be a payload too. */
    private @Nullable String recoverMessageId(final byte[] bytes) {
        final String id = A2aReader.recoverMessageId(bytes);
        return id == null || !detectors.run(List.of(new TextUnderCheck("messageId", -1, id))).isEmpty() ? null : id;
    }

    private String write(final Answers.Answer answer) throws IOException {
        final byte[] bytes = reader.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(answer.message());
        return FileOps.writeAtomically(config.feedback(), answer.fileName(), bytes).getFileName().toString();
    }

    /** A name that says which file it was to whoever has the original, and nothing to anybody else. */
    static String hashedName(final String name) {
        return "sha256-" + Redactor.sha256(name.getBytes(StandardCharsets.UTF_8)).substring(0, 12) + ".json";
    }

    /** Waits out the stability delay; a test puts a change to a file at exactly that moment. */
    interface Pause {
        void pause(Duration delay) throws InterruptedException;
    }

    /** What became of one file. */
    public enum Outcome {
        ACCEPTED, REJECTED, UNPROCESSABLE, ERROR, SET_ASIDE
    }

    /**
     * One file's result, safe to log: the name is shown only if it is plain, and every excerpt is redacted.
     *
     * @param name       the file's name as it may be shown
     * @param outcome    what became of it
     * @param findings   the findings that counted
     * @param answerFile the answer written to {@code feedback/}, or {@code null}
     * @param note       anything else worth a line
     */
    public record FileResult(String name, Outcome outcome, List<Finding> findings, @Nullable String answerFile,
            String note) {

        public FileResult {
            findings = List.copyOf(findings);
        }

        /** The log line: outcome, then one indented line per finding. */
        public String describe() {
            final StringBuilder sb = new StringBuilder();
            sb.append(name).append("   ").append(outcome);
            if (!findings.isEmpty()) {
                sb.append("  (").append(findings.size()).append(findings.size() == 1 ? " finding)" : " findings)");
            }
            if (!note.isEmpty()) {
                sb.append("  ").append(note);
            }
            for (final Finding f : findings) {
                sb.append("\n  [").append(f.severity()).append("] ").append(f.ruleId());
                if (f.location() != null) {
                    sb.append("  ").append(f.location());
                }
                if (f.start() >= 0) {
                    sb.append(' ').append(f.start()).append('-').append(f.end());
                }
                if (f.redactedExcerpt() != null) {
                    sb.append("  ").append(f.redactedExcerpt());
                }
            }
            if (answerFile != null) {
                sb.append("\n  answer → feedback/").append(answerFile);
            }
            return sb.toString();
        }

    }

    /**
     * One pass.
     *
     * @param results every file's result, in the order they were processed
     * @param elapsed how long the pass took
     */
    public record RunSummary(List<FileResult> results, Duration elapsed) {

        public RunSummary {
            results = List.copyOf(results);
        }

        public long count(final Outcome outcome) {
            return results.stream().filter(r -> r.outcome() == outcome).count();
        }

        /** 0 when everything was accepted, 1 when something was refused, 2 on a technical error. */
        public int exitCode() {
            if (count(Outcome.ERROR) > 0) {
                return 2;
            }
            return count(Outcome.REJECTED) + count(Outcome.UNPROCESSABLE) > 0 ? 1 : 0;
        }

        public String describe() {
            return "Summary: " + results.size() + " files - " + count(Outcome.ACCEPTED) + " accepted, "
                    + count(Outcome.REJECTED) + " rejected, " + count(Outcome.UNPROCESSABLE) + " unprocessable, "
                    + count(Outcome.ERROR) + " errors, " + count(Outcome.SET_ASIDE) + " set aside   ("
                    + elapsed.toMillis() + " ms)";
        }

    }

}
