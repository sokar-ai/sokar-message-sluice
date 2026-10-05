package org.fuin.sokar.msgsluice.filter.cli;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.fuin.sokar.msgsluice.filter.AgentCard;
import org.fuin.sokar.msgsluice.filter.Calibration;
import org.fuin.sokar.msgsluice.filter.ConfigException;
import org.fuin.sokar.msgsluice.filter.MessageSluice;
import org.fuin.sokar.msgsluice.filter.Settings;
import org.fuin.sokar.msgsluice.filter.io.DirectoryLock;
import org.jspecify.annotations.Nullable;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * The command line.
 *
 * <pre>
 * sokar-message-sluice --mail &lt;task state&gt;/mail [--blocking] [--watch] [--config file] [--&lt;key&gt; value ...]
 * sokar-message-sluice --dry-run --file msg.json [--&lt;key&gt; value ...]
 * sokar-message-sluice --calibrate [--dir &lt;messages&gt;] [--&lt;key&gt; value ...]   prints a properties file
 * sokar-message-sluice --agent-card --mail &lt;dir&gt;                                  prints its A2A agent card
 * </pre>
 *
 * Exit codes: 0 everything accepted, 1 something refused, 2 a technical error or a configuration that cannot
 * be used.
 */
public final class Main {

    private Main() {
    }

    public static void main(final String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    /** Everything but {@code System.exit}, so a test can run it. */
    public static int run(final String[] args, final PrintStream out, final PrintStream err) {
        try {
            return runChecked(args, out, err);
        } catch (final RuntimeException | Error ex) {
            // Escaping, it would end the JVM with 1, which says "something refused" rather than "not checked".
            // Only the type: a message may quote what was being read.
            err.println("sokar-message-sluice-filter: technical error: " + ex.getClass().getName());
            return 2;
        }
    }

    private static int runChecked(final String[] args, final PrintStream out, final PrintStream err) {
        final Map<String, String> cli = new LinkedHashMap<>();
        Path configFile = null;
        Path dryRunFile = null;
        boolean watch = false;
        boolean dryRun = false;
        boolean calibrate = false;
        boolean agentCard = false;
        Path calibrateDir = null;
        try {
            for (int i = 0; i < args.length; i++) {
                final String arg = args[i];
                switch (arg) {
                    case "--watch" -> watch = true;
                    case "--dry-run" -> dryRun = true;
                    case "--calibrate" -> calibrate = true;
                    case "--agent-card" -> agentCard = true;
                    case "--dir" -> calibrateDir = Path.of(value(args, ++i, arg));
                    case "--blocking" -> cli.put("blocking", "true");
                    case "--no-receipt" -> cli.put("receiptOnApproval", "false");
                    case "--config" -> configFile = Path.of(value(args, ++i, arg));
                    case "--file" -> dryRunFile = Path.of(value(args, ++i, arg));
                    case "--category" -> {
                        final String[] kv = value(args, ++i, arg).split("=", 2);
                        if (kv.length != 2) {
                            throw new ConfigException("--category takes CATEGORY=SEVERITY");
                        }
                        cli.put("decision.severity." + kv[0], kv[1]);
                    }
                    default -> {
                        if (!arg.startsWith("--") || arg.length() == 2) {
                            throw new ConfigException("Unexpected argument '" + arg + "'");
                        }
                        cli.put(arg.substring(2), value(args, ++i, arg));
                    }
                }
            }
            if (agentCard) {
                final Settings settings = Settings.load(configFile, cli);
                out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(
                        AgentCard.of(new ObjectMapper(), settings.config(), MessageSluice.version())));
                return 0;
            }
            if (calibrate) {
                return calibrate(calibrateDir, configFile, cli, out);
            }
            if (calibrateDir != null) {
                throw new ConfigException("--dir is only for --calibrate");
            }
            if (dryRun) {
                if (dryRunFile == null) {
                    throw new ConfigException("--dry-run needs --file");
                }
                return dryRun(dryRunFile, configFile, cli, out);
            }
            if (dryRunFile != null) {
                throw new ConfigException("--file is only for --dry-run");
            }
            final Settings settings = Settings.load(configFile, cli);
            final MessageSluice sluice = new MessageSluice(settings.config(), settings.detectors(),
                    Clock.systemUTC(), err::println);
            sluice.checkDirectories();
            err.println("sokar-message-sluice-filter " + MessageSluice.version() + " - "
                    + (settings.config().blocking() ? "BLOCKING: refused messages are refused"
                            : "REPORTING: nothing is refused for its content until blocking is switched on"));
            settings.describe().forEach(line -> err.println("  " + line));
            try (DirectoryLock lock = DirectoryLock.acquire(settings.config().lock())) {
                if (watch) {
                    sluice.watch(summary -> out.println(summary.describe()));
                    return 0;
                }
                final MessageSluice.RunSummary summary = sluice.runOnce();
                out.println(summary.describe());
                return summary.exitCode();
            }
        } catch (final ConfigException | DirectoryLock.LockedException ex) {
            err.println("sokar-message-sluice-filter: " + ex.getMessage());
            return 2;
        } catch (final IOException ex) {
            err.println("sokar-message-sluice-filter: " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
            return 2;
        }
    }

    private static int dryRun(final Path file, final @Nullable Path configFile, final Map<String, String> cli,
            final PrintStream out) throws ConfigException, IOException {
        // The directories are not used, so a dry run needs none of them.
        final Map<String, String> withDummies = new LinkedHashMap<>(cli);
        final Path absolute = file.toAbsolutePath();
        final Path parent = absolute.getParent();
        withDummies.putIfAbsent("mail", (parent == null ? absolute : parent).toString());
        final Settings settings = Settings.load(configFile, withDummies);
        final MessageSluice sluice = new MessageSluice(settings.config(), settings.detectors(), Clock.systemUTC(),
                line -> { });
        final MessageSluice.FileResult result = sluice.dryRun(file);
        out.println(result.describe());
        return switch (result.outcome()) {
            case ACCEPTED -> 0;
            case REJECTED, UNPROCESSABLE -> 1;
            default -> 2;
        };
    }

    /** Reads a directory, moves nothing, and prints a properties file. The directory defaults to the corpus. */
    private static int calibrate(final @Nullable Path dir, final @Nullable Path configFile,
            final Map<String, String> cli, final PrintStream out) throws ConfigException, IOException {
        final Map<String, String> withDummies = new LinkedHashMap<>(cli);
        if (dir != null) {
            withDummies.putIfAbsent("mail", dir.toAbsolutePath().toString());
        }
        final Settings settings = Settings.load(configFile, withDummies);
        final Path target = dir != null ? dir : settings.config().corpus();
        if (!Files.isDirectory(target)) {
            throw new ConfigException("Not a directory: " + target);
        }
        out.print(new Calibration(settings).run(target));
        return 0;
    }

    private static String value(final String[] args, final int i, final String option) throws ConfigException {
        if (i >= args.length) {
            throw new ConfigException(option + " needs a value");
        }
        return args[i];
    }

    /** For a test: the options this command line knows beside the configuration keys. */
    static List<String> flags() {
        return List.of("--watch", "--dry-run", "--calibrate", "--agent-card", "--dir", "--blocking", "--no-receipt", "--config",
                "--file", "--category");
    }

}
