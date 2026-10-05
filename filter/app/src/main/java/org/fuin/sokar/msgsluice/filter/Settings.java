package org.fuin.sokar.msgsluice.filter;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.fuin.sokar.msgsluice.filter.a2a.CheckConfig;
import org.fuin.sokar.msgsluice.filter.a2a.EnvelopeCheck;
import org.fuin.sokar.msgsluice.filter.decision.DecisionConfig;
import org.fuin.sokar.msgsluice.filter.decision.Redactor;
import org.fuin.sokar.msgsluice.filter.decision.Severity;
import org.fuin.sokar.msgsluice.filter.detect.ContentDetector;
import org.fuin.sokar.msgsluice.filter.detect.DistributionDetector;
import org.fuin.sokar.msgsluice.filter.detect.EncodingSignatureDetector;
import org.fuin.sokar.msgsluice.filter.detect.EntropyDetector;
import org.fuin.sokar.msgsluice.filter.detect.LongTokenDetector;
import org.fuin.sokar.msgsluice.filter.detect.Normalizer;
import org.fuin.sokar.msgsluice.filter.detect.TokenShapeDetector;
import org.jspecify.annotations.Nullable;

/**
 * The configuration, later sources beating earlier: built-in defaults, a properties file, command-line options.
 * Never the environment: what decides whether a message may leave is configured where somebody wrote it on
 * purpose, not by whatever a shell, a profile or an agent's session had exported.
 *
 * <p>
 * An unknown key aborts the start. A typo in a threshold's name would otherwise silently leave the default in
 * place, and a configuration that quietly differs from what was intended is indistinguishable from a working
 * check.
 */
public final class Settings {

    private static final String WEIGHT = "decision.weight.";

    private static final String SEVERITY = "decision.severity.";

    /** Every plain key and its default; an empty default means none. In the order they are logged. */
    private static final Map<String, String> DEFAULTS = new LinkedHashMap<>();

    static {
        DEFAULTS.put("mail", "");
        DEFAULTS.put("incoming", "");
        DEFAULTS.put("accepted", "");
        DEFAULTS.put("corpus", "");
        DEFAULTS.put("feedback", "");
        DEFAULTS.put("rejected", "");
        DEFAULTS.put("error", "");
        DEFAULTS.put("lock", "");
        DEFAULTS.put("blocking", "false");
        DEFAULTS.put("receiptOnApproval", "true");
        DEFAULTS.put("stabilityDelayMillis", "200");
        DEFAULTS.put("watchIntervalMillis", "2000");
        final CheckConfig check = CheckConfig.defaults();
        DEFAULTS.put("check.allowedRoles", String.join(",", new java.util.TreeSet<>(check.allowedRoles())));
        DEFAULTS.put("check.urlPartSeverity", check.urlPartSeverity().name());
        DEFAULTS.put("check.maxParts", String.valueOf(check.maxParts()));
        DEFAULTS.put("check.maxTextLengthPerPart", String.valueOf(check.maxTextLengthPerPart()));
        DEFAULTS.put("check.maxFileSizeBytes", String.valueOf(check.maxFileSizeBytes()));
        DEFAULTS.put("check.maxIdLength", String.valueOf(check.maxIdLength()));
        DEFAULTS.put("check.maxMetadataDepth", String.valueOf(check.maxMetadataDepth()));
        DEFAULTS.put("check.maxMetadataChars", String.valueOf(check.maxMetadataChars()));
        DEFAULTS.put("check.maxReferenceTaskIds", String.valueOf(check.maxReferenceTaskIds()));
        final DecisionConfig decision = DecisionConfig.defaults();
        DEFAULTS.put("decision.mode", decision.mode().name());
        DEFAULTS.put("decision.suspiciousPolicy", decision.suspiciousPolicy().name());
        DEFAULTS.put("decision.suspiciousCombineCount", String.valueOf(decision.suspiciousCombineCount()));
        DEFAULTS.put("decision.scoreThreshold", String.valueOf(decision.scoreThreshold()));
        DEFAULTS.put("decision.disabledRules", "");
        DEFAULTS.put("redaction.mode", Redactor.Mode.PARTIAL.name());
        DEFAULTS.put("detector.longToken.enabled", "true");
        DEFAULTS.put("detector.longToken.maxTokenLength", String.valueOf(LongTokenDetector.DEFAULT_MAX_TOKEN_LENGTH));
        // Every default here was measured - see doc/detectors.md.
        DEFAULTS.put("detector.tokenShape.enabled", "true");
        DEFAULTS.put("detector.tokenShape.maxDigitUpperShare", "0.5");
        DEFAULTS.put("detector.tokenShape.minVowelShare", "0.15");
        DEFAULTS.put("detector.tokenShape.maxSymbolShare", "0.2");
        DEFAULTS.put("detector.entropy.enabled", "true");
        DEFAULTS.put("detector.entropy.threshold", "4.5");
        DEFAULTS.put("detector.entropy.windowSize", "64");
        DEFAULTS.put("detector.entropy.step", "16");
        DEFAULTS.put("detector.entropy.minLength", "64");
        DEFAULTS.put("detector.distribution.enabled", "true");
        DEFAULTS.put("detector.distribution.minLength", "200");
        DEFAULTS.put("detector.distribution.maxChiSquarePerLetter", "2.0");
        DEFAULTS.put("detector.distribution.minWhitespaceShare", "0.08");
        DEFAULTS.put("detector.signature.enabled", "true");
        DEFAULTS.put("detector.signature.minLength", "32");
    }

    /** Directory keys a {@code mail} root supplies when they are not set themselves. */
    private static final Map<String, String> UNDER_MAIL = Map.of("incoming", "incoming", "accepted",
            "filter/accepted", "corpus", "sent", "feedback", "filter/feedback", "rejected", "filter/rejected",
            "error", "filter/error", "lock", "filter/.lock");

    private final Map<String, String> values;

    private final Map<String, String> sources;

    private final List<ContentDetector> detectors;

    private final FilterConfig config;

    private Settings(final Map<String, String> values, final Map<String, String> sources) throws ConfigException {
        this.values = values;
        this.sources = sources;
        this.detectors = buildDetectors();
        this.config = buildConfig();
    }

    /**
     * @param file the properties file, or {@code null}
     * @param cli  keys and values given on the command line
     */
    public static Settings load(final @Nullable Path file, final Map<String, String> cli)
            throws ConfigException {
        final Map<String, String> values = new HashMap<>(DEFAULTS);
        final Map<String, String> sources = new HashMap<>();
        DEFAULTS.keySet().forEach(k -> sources.put(k, "default"));

        if (file != null) {
            final Properties properties = new Properties();
            try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                properties.load(reader);
            } catch (final IOException ex) {
                throw new ConfigException("Cannot read the configuration file " + file + ": " + ex.getMessage());
            }
            for (final String key : properties.stringPropertyNames()) {
                set(values, sources, key, properties.getProperty(key), "file " + file);
            }
        }
        for (final Map.Entry<String, String> e : cli.entrySet()) {
            set(values, sources, e.getKey(), e.getValue(), "command line");
        }

        final String mail = valueIn(values, "mail");
        if (!mail.isBlank()) {
            for (final Map.Entry<String, String> e : UNDER_MAIL.entrySet()) {
                if (valueIn(values, e.getKey()).isBlank()) {
                    values.put(e.getKey(), Path.of(mail).resolve(e.getValue()).toString());
                    sources.put(e.getKey(), "under mail");
                }
            }
        }
        return new Settings(values, sources);
    }

    private static void set(final Map<String, String> values, final Map<String, String> sources, final String key,
            final String value, final String source) throws ConfigException {
        if (!DEFAULTS.containsKey(key) && !key.startsWith(WEIGHT) && !key.startsWith(SEVERITY)) {
            throw new ConfigException("Unknown configuration key '" + key + "' (" + source + ")");
        }
        values.put(key, value.strip());
        sources.put(key, source);
    }

    /** Every key read is a default or one set over a default, so a missing one is a defect here, not a setting. */
    private static String valueIn(final Map<String, String> values, final String key) {
        final String value = values.get(key);
        if (value == null) {
            throw new IllegalStateException("No value for the configuration key '" + key + "'");
        }
        return value;
    }

    /** An exception without a message still says what went wrong. */
    private static String reason(final RuntimeException ex) {
        final String message = ex.getMessage();
        return message == null ? ex.getClass().getSimpleName() : message;
    }

    public FilterConfig config() {
        return config;
    }

    public List<ContentDetector> detectors() {
        return detectors;
    }

    /** The effective value of a key, as configured. */
    public String value(final String key) {
        return valueIn(values, key);
    }

    /** The effective value of a key that holds a positive whole number. */
    public int intValue(final String key) {
        try {
            return positiveInt(key);
        } catch (final ConfigException ex) {
            throw new IllegalStateException(ex.getMessage(), ex);
        }
    }

    /** The effective configuration, one line per key with where it came from, for the startup log. */
    public List<String> describe() {
        return new TreeMap<>(values).entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue() + "  (" + sources.get(e.getKey()) + ")").toList();
    }

    private List<ContentDetector> buildDetectors() throws ConfigException {
        final List<ContentDetector> list = new ArrayList<>();
        if (bool("detector.longToken.enabled")) {
            list.add(new LongTokenDetector(positiveInt("detector.longToken.maxTokenLength")));
        }
        try {
            if (bool("detector.tokenShape.enabled")) {
                list.add(new TokenShapeDetector(share("detector.tokenShape.maxDigitUpperShare"),
                        share("detector.tokenShape.minVowelShare"), share("detector.tokenShape.maxSymbolShare")));
            }
            if (bool("detector.entropy.enabled")) {
                list.add(new EntropyDetector(nonNegativeDouble("detector.entropy.threshold"),
                        positiveInt("detector.entropy.windowSize"), positiveInt("detector.entropy.step"),
                        positiveInt("detector.entropy.minLength")));
            }
            if (bool("detector.distribution.enabled")) {
                list.add(new DistributionDetector(positiveInt("detector.distribution.minLength"),
                        nonNegativeDouble("detector.distribution.maxChiSquarePerLetter"),
                        share("detector.distribution.minWhitespaceShare")));
            }
            if (bool("detector.signature.enabled")) {
                list.add(new EncodingSignatureDetector(positiveInt("detector.signature.minLength")));
            }
        } catch (final IllegalArgumentException ex) {
            throw new ConfigException(reason(ex));
        }
        return List.copyOf(list);
    }

    private FilterConfig buildConfig() throws ConfigException {
        final CheckConfig check;
        try {
            check = new CheckConfig(roles("check.allowedRoles"), severity("check.urlPartSeverity"),
                    positiveInt("check.maxParts"), positiveInt("check.maxTextLengthPerPart"),
                    positiveLong("check.maxFileSizeBytes"), positiveInt("check.maxIdLength"),
                    positiveInt("check.maxMetadataDepth"), positiveInt("check.maxMetadataChars"),
                    positiveInt("check.maxReferenceTaskIds"));
        } catch (final IllegalArgumentException ex) {
            throw new ConfigException(reason(ex));
        }

        // The normalizer's rules count as a detector's: they can be weighed, re-graded and disabled.
        final Set<String> detectorRules = Stream.concat(Normalizer.RULE_IDS.stream(),
                detectors.stream().flatMap(d -> d.ruleIds().stream())).collect(Collectors.toSet());
        final Set<String> categories = Stream.concat(Stream.of(Normalizer.CATEGORY),
                detectors.stream().flatMap(d -> d.categories().stream())).collect(Collectors.toSet());
        final Map<String, Double> weights = new HashMap<>();
        final Map<String, Severity> overrides = new HashMap<>();
        for (final Map.Entry<String, String> e : values.entrySet()) {
            if (e.getKey().startsWith(WEIGHT)) {
                final String rule = e.getKey().substring(WEIGHT.length());
                if (!detectorRules.contains(rule) && !EnvelopeCheck.RULE_IDS.contains(rule)) {
                    throw new ConfigException("Unknown rule '" + rule + "' in " + e.getKey());
                }
                weights.put(rule, nonNegativeDouble(e.getKey()));
            } else if (e.getKey().startsWith(SEVERITY)) {
                final String category = e.getKey().substring(SEVERITY.length());
                if (!categories.contains(category)) {
                    throw new ConfigException("Unknown category '" + category + "' in " + e.getKey()
                            + "; the envelope's severities are not configurable");
                }
                overrides.put(category, severity(e.getKey()));
            }
        }
        final Set<String> disabled = Arrays.stream(valueIn(values, "decision.disabledRules").split(","))
                .map(String::strip).filter(s -> !s.isEmpty()).collect(Collectors.toSet());
        for (final String rule : disabled) {
            if (!detectorRules.contains(rule)) {
                throw new ConfigException("Cannot disable '" + rule + "': "
                        + (EnvelopeCheck.RULE_IDS.contains(rule) ? "the envelope's rules always apply"
                                : "no such rule"));
            }
        }
        final DecisionConfig.Mode mode = enumValue(DecisionConfig.Mode.class, "decision.mode");
        if (mode != DecisionConfig.Mode.SCORE && !weights.isEmpty()) {
            // Only the score reads a weight; one set in another mode would be a check that quietly differs.
            throw new ConfigException("'" + WEIGHT + new TreeMap<>(weights).firstKey() + "' has no effect unless "
                    + "decision.mode is SCORE");
        }
        if (mode != DecisionConfig.Mode.SCORE
                && !valueIn(values, "decision.scoreThreshold").equals(DEFAULTS.get("decision.scoreThreshold"))) {
            // The same for the threshold: the default is always present, so only a changed value was set on purpose.
            throw new ConfigException("'decision.scoreThreshold' has no effect unless decision.mode is SCORE");
        }
        final DecisionConfig decision;
        try {
            decision = new DecisionConfig(mode,
                    enumValue(DecisionConfig.SuspiciousPolicy.class, "decision.suspiciousPolicy"),
                    positiveInt("decision.suspiciousCombineCount"), nonNegativeDouble("decision.scoreThreshold"),
                    weights, disabled, overrides);
        } catch (final IllegalArgumentException ex) {
            throw new ConfigException(reason(ex));
        }

        return new FilterConfig(path("incoming"), path("accepted"), path("corpus"), path("feedback"),
                path("rejected"), path("error"), path("lock"), check, decision,
                enumValue(Redactor.Mode.class, "redaction.mode"), bool("blocking"), bool("receiptOnApproval"),
                Duration.ofMillis(nonNegativeLong("stabilityDelayMillis")),
                Duration.ofMillis(positiveLong("watchIntervalMillis")));
    }

    private Path path(final String key) throws ConfigException {
        final String value = valueIn(values, key);
        if (value.isBlank()) {
            throw new ConfigException("'" + key + "' is not set, and no 'mail' directory supplies it");
        }
        return Path.of(value);
    }

    private boolean bool(final String key) throws ConfigException {
        final String value = valueIn(values, key);
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "true" -> true;
            case "false" -> false;
            default -> throw new ConfigException("'" + key + "' must be true or false: " + value);
        };
    }

    private int positiveInt(final String key) throws ConfigException {
        final long value = positiveLong(key);
        if (value > Integer.MAX_VALUE) {
            throw new ConfigException("'" + key + "' is too large: " + value);
        }
        return (int) value;
    }

    private long positiveLong(final String key) throws ConfigException {
        final long value = nonNegativeLong(key);
        if (value < 1) {
            throw new ConfigException("'" + key + "' must be positive: " + value);
        }
        return value;
    }

    private long nonNegativeLong(final String key) throws ConfigException {
        try {
            final long value = Long.parseLong(valueIn(values, key));
            if (value < 0) {
                throw new ConfigException("'" + key + "' must not be negative: " + value);
            }
            return value;
        } catch (final NumberFormatException ex) {
            throw new ConfigException("'" + key + "' is not a whole number: " + valueIn(values, key));
        }
    }

    private double nonNegativeDouble(final String key) throws ConfigException {
        try {
            final double value = Double.parseDouble(valueIn(values, key));
            if (!(value >= 0.0) || Double.isInfinite(value)) {
                throw new ConfigException("'" + key + "' must be a non-negative number: " + value);
            }
            return value;
        } catch (final NumberFormatException ex) {
            throw new ConfigException("'" + key + "' is not a number: " + valueIn(values, key));
        }
    }

    private Set<String> roles(final String key) throws ConfigException {
        final Set<String> roles = Arrays.stream(valueIn(values, key).split(",")).map(String::strip)
                .filter(s -> !s.isEmpty()).collect(Collectors.toSet());
        for (final String role : roles) {
            if (!Set.of("ROLE_AGENT", "ROLE_USER", "ROLE_UNSPECIFIED").contains(role)) {
                throw new ConfigException("'" + key + "' names an unknown role: " + role);
            }
        }
        return roles;
    }

    private double share(final String key) throws ConfigException {
        final double value = nonNegativeDouble(key);
        if (value > 1.0) {
            throw new ConfigException("'" + key + "' is a share between 0 and 1: " + value);
        }
        return value;
    }

    private Severity severity(final String key) throws ConfigException {
        return enumValue(Severity.class, key);
    }

    private <E extends Enum<E>> E enumValue(final Class<E> type, final String key) throws ConfigException {
        final String value = valueIn(values, key);
        try {
            return Enum.valueOf(type, value.toUpperCase(Locale.ROOT));
        } catch (final IllegalArgumentException ex) {
            throw new ConfigException("'" + key + "' must be one of " + Arrays.toString(type.getEnumConstants())
                    + ": " + value);
        }
    }

}
