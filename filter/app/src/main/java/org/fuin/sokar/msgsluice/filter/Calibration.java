package org.fuin.sokar.msgsluice.filter;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

import org.fuin.sokar.msgsluice.filter.a2a.A2aReader;
import org.fuin.sokar.msgsluice.filter.a2a.EnvelopeCheck;
import org.fuin.sokar.msgsluice.filter.a2a.EnvelopeResult;
import org.fuin.sokar.msgsluice.filter.a2a.Unprocessable;
import org.fuin.sokar.msgsluice.filter.decision.DecisionModel;
import org.fuin.sokar.msgsluice.filter.decision.Finding;
import org.fuin.sokar.msgsluice.filter.decision.Redactor;
import org.fuin.sokar.msgsluice.filter.io.FileOps;
import org.fuin.sokar.msgsluice.filter.detect.DetectorRunner;
import org.fuin.sokar.msgsluice.filter.detect.DistributionDetector;
import org.fuin.sokar.msgsluice.filter.detect.EntropyDetector;
import org.fuin.sokar.msgsluice.filter.detect.Masked;
import org.fuin.sokar.msgsluice.filter.detect.Normalizer;
import org.fuin.sokar.msgsluice.filter.detect.TextUnderCheck;

/**
 * Calibration: checks a directory of messages without moving anything, and prints what it measured as a
 * properties file the filter reads. Point it at a mailbox's own traffic - its {@code sent/}, say - before
 * switching that mailbox to blocking.
 *
 * <p>
 * For each threshold it reports the distribution over the directory and, beside it, the same measure over random
 * data encoded as base64, generated here. The suggestion lies between the 99th percentile of the directory and
 * the 5th of the encodings - see doc/detectors.md. Where the two overlap it keeps the current value and
 * says that the directory cannot be told apart from encoded data on this measure.
 */
public final class Calibration {

    private final Settings settings;

    public Calibration(final Settings settings) {
        this.settings = settings;
    }

    /** The report, as the text of a properties file. */
    public String run(final Path dir) throws IOException {
        final FilterConfig config = settings.config();
        final A2aReader reader = new A2aReader();
        final EnvelopeCheck envelope = new EnvelopeCheck(config.check());
        final DetectorRunner runner = new DetectorRunner(settings.detectors(), new Redactor(config.redaction()));
        final DecisionModel model = new DecisionModel(config.decision());

        final int window = settings.intValue("detector.entropy.windowSize");
        final int step = settings.intValue("detector.entropy.step");
        final int minEntropyLength = settings.intValue("detector.entropy.minLength");
        final int minDistribution = settings.intValue("detector.distribution.minLength");

        final List<Double> entropy = new ArrayList<>();
        final List<Double> chi = new ArrayList<>();
        final List<Double> whitespace = new ArrayList<>();
        final Map<String, Integer> byRule = new TreeMap<>();
        int messages = 0;
        int unprocessable = 0;
        int texts = 0;
        int wouldRefuse = 0;

        final List<Path> files = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.json")) {
            stream.forEach(files::add);
        }
        Collections.sort(files);
        for (final Path file : files) {
            // As the filter itself reads: a plain file with one name, never through a link, never past the most a
            // message may be. Anything else is counted as no message.
            final FileOps.Stamp stamp = FileOps.stamp(file);
            final byte[] bytes = stamp != null && stamp.plain() && stamp.size() <= config.check().maxFileSizeBytes()
                    ? FileOps.read(file, config.check().maxFileSizeBytes()).bytes()
                    : null;
            final EnvelopeResult result;
            try {
                if (bytes == null) {
                    throw new Unprocessable("FILE/NOT_PLAIN", "not a plain file of a message's size");
                }
                result = envelope.check(reader.parse(bytes));
            } catch (final Unprocessable ex) {
                unprocessable++;
                continue;
            }
            messages++;
            final List<Finding> findings = new ArrayList<>(result.findings());
            findings.addAll(runner.run(result.texts()));
            findings.forEach(f -> byRule.merge(f.ruleId(), 1, Integer::sum));
            if (model.decide(findings, true).wouldReject()) {
                wouldRefuse++;
            }
            for (final TextUnderCheck text : result.texts()) {
                texts++;
                final String masked = Masked.of(Normalizer.normalize(text.text()).text()).text();
                if (masked.length() >= minEntropyLength) {
                    entropy.add(maxEntropy(masked, window, step));
                }
                if (masked.strip().length() >= minDistribution) {
                    chi.add(DistributionDetector.chiSquarePerLetter(masked));
                    whitespace.add(DistributionDetector.whitespaceShare(masked));
                }
            }
        }

        final Reference reference = reference(window, step, minDistribution);
        final StringBuilder out = new StringBuilder();
        out.append("# sokar-message-sluice calibration over ").append(dir).append('\n');
        out.append(String.format(Locale.ROOT, "# %d messages, %d texts, %d files unprocessable%n", messages, texts,
                unprocessable));
        out.append(String.format(Locale.ROOT, "# with the current settings, blocking mode would refuse %d (%s)%n",
                wouldRefuse, percent(wouldRefuse, messages)));
        out.append("# findings per rule: ").append(byRule.isEmpty() ? "none" : byRule.toString()).append("\n\n");

        suggestAbove(out, "detector.entropy.threshold", entropy, reference.entropy, 2);
        suggestAbove(out, "detector.distribution.maxChiSquarePerLetter", chi, reference.chi, 2);
        suggestBelow(out, "detector.distribution.minWhitespaceShare", whitespace, reference.whitespace, 3);
        return out.toString();
    }

    /** A value above everything the directory does and below what encodings do. */
    private void suggestAbove(final StringBuilder out, final String key, final List<Double> observed,
            final List<Double> encoded, final int decimals) {
        header(out, key, observed, encoded);
        final String current = settings.value(key);
        if (observed.isEmpty()) {
            out.append("# nothing in the directory was long enough to measure; the current value stays\n");
            out.append(key).append('=').append(current).append("\n\n");
            return;
        }
        final double clean = percentile(observed, 99);
        final double data = percentile(encoded, 5);
        if (clean < data) {
            out.append(key).append('=').append(format((clean + data) / 2, decimals)).append("\n\n");
        } else {
            out.append("# the directory reaches what encoded data does: this measure cannot tell them apart here\n");
            out.append(key).append('=').append(current).append("\n\n");
        }
    }

    /** A value below everything the directory does and above what encodings do. */
    private void suggestBelow(final StringBuilder out, final String key, final List<Double> observed,
            final List<Double> encoded, final int decimals) {
        header(out, key, observed, encoded);
        final String current = settings.value(key);
        if (observed.isEmpty()) {
            out.append("# nothing in the directory was long enough to measure; the current value stays\n");
            out.append(key).append('=').append(current).append("\n\n");
            return;
        }
        final double clean = percentile(observed, 1);
        final double data = percentile(encoded, 95);
        if (clean > data) {
            out.append(key).append('=').append(format((clean + data) / 2, decimals)).append("\n\n");
        } else {
            out.append("# the directory reaches what encoded data does: this measure cannot tell them apart here\n");
            out.append(key).append('=').append(current).append("\n\n");
        }
    }

    private void header(final StringBuilder out, final String key, final List<Double> observed,
            final List<Double> encoded) {
        out.append("# ").append(key).append(" (now ").append(settings.value(key)).append(")\n");
        out.append("#   directory ").append(distribution(observed)).append('\n');
        out.append("#   base64    ").append(distribution(encoded)).append('\n');
    }

    /** Random bytes as base64, in an English sentence, measured the same way as the directory. */
    private record Reference(List<Double> entropy, List<Double> chi, List<Double> whitespace) {
    }

    private static Reference reference(final int window, final int step, final int minDistribution) {
        final Random random = new Random(20260918L);
        final List<Double> entropy = new ArrayList<>();
        final List<Double> chi = new ArrayList<>();
        final List<Double> whitespace = new ArrayList<>();
        for (int i = 0; i < 400; i++) {
            final byte[] bytes = new byte[Math.max(minDistribution, window)];
            random.nextBytes(bytes);
            final String payload = Base64.getEncoder().encodeToString(bytes);
            final String text = "Here is the file: " + payload.substring(0, window) + " - thanks.";
            entropy.add(maxEntropy(Masked.of(text).text(), window, step));
            chi.add(DistributionDetector.chiSquarePerLetter(payload));
            whitespace.add(DistributionDetector.whitespaceShare(payload));
        }
        return new Reference(entropy, chi, whitespace);
    }

    static double maxEntropy(final String text, final int window, final int step) {
        final String folded = EntropyDetector.fold(text);
        final int size = Math.min(window, folded.length());
        double max = 0.0;
        for (final int start : EntropyDetector.windowStarts(folded.length(), window, step)) {
            max = Math.max(max, EntropyDetector.entropy(folded, start, start + size));
        }
        return max;
    }

    private static String distribution(final List<Double> values) {
        if (values.isEmpty()) {
            return "no values";
        }
        return String.format(Locale.ROOT, "n=%d  min %.3f  median %.3f  p95 %.3f  p99 %.3f  max %.3f",
                values.size(), percentile(values, 0), percentile(values, 50), percentile(values, 95),
                percentile(values, 99), percentile(values, 100));
    }

    static double percentile(final List<Double> values, final int p) {
        final List<Double> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        final int index = (int) Math.ceil(p / 100.0 * sorted.size()) - 1;
        return sorted.get(Math.max(0, Math.min(sorted.size() - 1, index)));
    }

    private static String format(final double value, final int decimals) {
        return String.format(Locale.ROOT, "%." + decimals + "f", value);
    }

    private static String percent(final int part, final int whole) {
        return whole == 0 ? "0 %" : String.format(Locale.ROOT, "%.1f %%", 100.0 * part / whole);
    }

}
