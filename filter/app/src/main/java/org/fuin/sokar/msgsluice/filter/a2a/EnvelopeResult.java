package org.fuin.sokar.msgsluice.filter.a2a;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.fuin.sokar.msgsluice.filter.decision.Finding;
import org.fuin.sokar.msgsluice.filter.detect.TextUnderCheck;

/**
 * What stage A found, and every text it hands on to the detectors.
 *
 * @param facts     the ids an answer refers back to
 * @param findings  stage A's own findings
 * @param texts     every string the envelope did not validate structurally, in document order
 * @param shownKeys every location that names a free-form key in clear, mapped to the same location naming it by
 *                  its position
 */
public record EnvelopeResult(MessageFacts facts, List<Finding> findings, List<TextUnderCheck> texts,
        Map<String, String> shownKeys) {

    public EnvelopeResult {
        Objects.requireNonNull(facts, "facts");
        findings = List.copyOf(findings);
        texts = List.copyOf(texts);
        shownKeys = Map.copyOf(shownKeys);
    }

    /**
     * The facts an answer may echo: an id that anything was found at is left out, because an answer must not
     * carry what a rule matched.
     */
    public MessageFacts echoable(final List<Finding> all) {
        final Set<String> hit = locations(all);
        return new MessageFacts(hit.contains("messageId") ? null : facts.messageId(),
                hit.contains("contextId") ? null : facts.contextId(),
                hit.contains("taskId") || hit.contains("id") ? null : facts.taskId());
    }

    /**
     * The findings with every key that could be what a rule matched named by its position rather than in clear:
     * a key anything was found in, every key above a finding - a key the detectors passed can still be text its
     * writer would not want in an answer or a log line - and every key when the detectors did not run and nothing
     * vouches for any.
     *
     * @param all           every finding, envelope and detectors alike
     * @param detectorsRan  whether the detectors looked at the keys at all
     */
    public List<Finding> withKeysHidden(final List<Finding> all, final boolean detectorsRan) {
        final Set<String> hit = locations(all);
        // Longest first: a hidden key below a hidden key is rewritten before its parent's prefix is.
        final List<Map.Entry<String, String>> hide = shownKeys.entrySet().stream()
                .filter(e -> !detectorsRan || hit.stream().anyMatch(at -> under(at, e.getKey())))
                .sorted(Comparator.comparingInt((Map.Entry<String, String> e) -> e.getKey().length()).reversed())
                .toList();
        if (hide.isEmpty()) {
            return all;
        }
        return all.stream().map(f -> f.location() == null ? f : f.withLocation(hidden(f.location(), hide)))
                .toList();
    }

    /** Whether a finding's location is the key itself, the value it names, or anything below it. */
    private static boolean under(final String location, final String key) {
        return location.equals(key) || location.startsWith(key + "(") || location.startsWith(key + ".")
                || location.startsWith(key + "[");
    }

    private static String hidden(final String location, final List<Map.Entry<String, String>> hide) {
        String result = location;
        for (final Map.Entry<String, String> key : hide) {
            final String clear = key.getKey();
            if (result.startsWith(clear)
                    && (result.length() == clear.length() || ".[(".indexOf(result.charAt(clear.length())) >= 0)) {
                result = key.getValue() + result.substring(clear.length());
            }
        }
        return result;
    }

    private static Set<String> locations(final List<Finding> all) {
        return all.stream().map(Finding::location).filter(Objects::nonNull).collect(Collectors.toSet());
    }

}
