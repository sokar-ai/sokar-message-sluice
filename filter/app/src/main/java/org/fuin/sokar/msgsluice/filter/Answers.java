package org.fuin.sokar.msgsluice.filter;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

import org.fuin.sokar.msgsluice.filter.a2a.MessageFacts;
import org.fuin.sokar.msgsluice.filter.decision.Finding;
import org.fuin.sokar.msgsluice.filter.decision.Redactor;
import org.fuin.sokar.msgsluice.filter.decision.Verdict;
import org.jspecify.annotations.Nullable;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Builds the answers: a receipt or a rejection, each itself a valid A2A 1.0 message with {@code ROLE_AGENT}, a
 * text part a person or an agent can read and a {@code data} part a program can. Nothing goes in that a
 * finding matched: every excerpt is already redacted, and ids are echoed only when they passed the id check.
 */
public final class Answers {

    public static final String TOOL_NAME = "sokar-message-sluice-filter";

    private static final DateTimeFormatter FILE_TIME = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmssSSS'Z'")
            .withZone(ZoneOffset.UTC);

    private static final Pattern SAFE_FILE_NAME = Pattern.compile("[A-Za-z0-9._-]{1,64}");

    private final ObjectMapper mapper;

    private final String version;

    private final List<String> detectorIds;

    public Answers(final ObjectMapper mapper, final String version, final List<String> detectorIds) {
        this.mapper = Objects.requireNonNull(mapper, "mapper");
        this.version = Objects.requireNonNull(version, "version");
        this.detectorIds = List.copyOf(detectorIds);
    }

    /** An answer, and the name it is written under. */
    public record Answer(String fileName, ObjectNode message) {
    }

    /** The answer to a message that could be judged: a receipt when it was accepted, a rejection otherwise. */
    public Answer verdict(final MessageFacts facts, final Verdict verdict, final boolean blocking, final Instant now) {
        final StringBuilder text = new StringBuilder();
        if (verdict.accepted()) {
            text.append("Your message was accepted and handed on for delivery.");
            if (!blocking && verdict.wouldReject()) {
                text.append(" This mailbox is still being calibrated and only reports: in blocking mode the message ")
                        .append("would have been refused for the reasons below.");
            }
        } else {
            text.append("Your message was not accepted, and nothing of it was sent.");
            text.append(" Only plain English prose may leave; send it again without what is listed below.");
        }
        appendFindings(text, verdict.findings());

        final ObjectNode data = mapper.createObjectNode();
        data.put("decision", verdict.accepted() ? "approved" : "rejected");
        data.put("mode", blocking ? "blocking" : "reporting");
        data.put("wouldReject", verdict.wouldReject());
        if (verdict.decidingRule() != null) {
            data.put("decidingRule", verdict.decidingRule());
        }
        if (facts.messageId() != null) {
            data.put(verdict.accepted() ? "messageId" : "rejectedMessageId", facts.messageId());
        }
        common(data, now);
        final ArrayNode findings = data.putArray("findings");
        verdict.findings().forEach(f -> findings.add(finding(f)));
        return answer(facts, text.toString(), data, now);
    }

    /**
     * The rejection of a file that could not be judged at all. It carries no excerpt of the content - a payload
     * wrapped in broken JSON would otherwise be a direct bypass - only the file's name, size and hash.
     */
    public Answer unprocessable(final String ruleId, final String reason, final String sourceFileName,
            final String sourceSha256, final long sourceSize, final @Nullable String recoveredMessageId,
            final MessageFacts facts, final Instant now) {
        final String text = "Your message could not be read as an A2A 1.0 message, so it was not accepted and "
                + "nothing of it was sent.\n1. [BLOCKING] " + ruleId + ": " + reason;
        final ObjectNode data = mapper.createObjectNode();
        data.put("decision", "rejected");
        data.put("rejectionKind", "unprocessable");
        data.put("ruleId", ruleId);
        data.put("reason", reason);
        data.put("sourceFileName", safeFileName(sourceFileName));
        data.put("sourceSha256", sourceSha256);
        data.put("sourceSizeBytes", sourceSize);
        if (recoveredMessageId != null) {
            // Marked as recovered: it was found by a tolerant scan, not read from a valid message.
            data.put("recoveredMessageId", recoveredMessageId);
        }
        common(data, now);
        return answer(facts, text, data, now);
    }

    /** A file name as it may appear in an answer or a log line: itself if short and plain, otherwise its hash. */
    public static String safeFileName(final String name) {
        return SAFE_FILE_NAME.matcher(name).matches() ? name
                : "sha256:" + Redactor.sha256(name.getBytes(StandardCharsets.UTF_8)).substring(0, 12);
    }

    private void common(final ObjectNode data, final Instant now) {
        data.put("checkedAt", now.toString());
        final ObjectNode tool = data.putObject("tool");
        tool.put("name", TOOL_NAME);
        tool.put("version", version);
        final ArrayNode detectors = data.putArray("detectors");
        detectorIds.forEach(detectors::add);
    }

    private Answer answer(final MessageFacts facts, final String text, final ObjectNode data, final Instant now) {
        final String messageId = "sluice-" + UUID.randomUUID();
        final ObjectNode message = mapper.createObjectNode();
        message.put("messageId", messageId);
        message.put("role", "ROLE_AGENT");
        if (facts.contextId() != null) {
            message.put("contextId", facts.contextId());
        }
        if (facts.taskId() != null) {
            message.put("taskId", facts.taskId());
        }
        final ArrayNode parts = message.putArray("parts");
        parts.addObject().put("text", text).put("mediaType", "text/plain");
        parts.addObject().set("data", data);
        if (facts.messageId() != null) {
            // A2A has no standard field for the relation.
            message.putObject("metadata").put("inReplyToMessageId", facts.messageId());
        }
        return new Answer(FILE_TIME.format(now) + "--" + messageId + ".json", message);
    }

    private ObjectNode finding(final Finding f) {
        final ObjectNode node = mapper.createObjectNode();
        node.put("ruleId", f.ruleId());
        node.put("stage", f.stage().name());
        node.put("severity", f.severity().name());
        node.put("category", f.category());
        if (f.location() != null) {
            node.put("location", f.location());
        }
        node.put("partIndex", f.partIndex());
        node.put("start", f.start());
        node.put("end", f.end());
        if (f.redactedExcerpt() != null) {
            node.put("redactedExcerpt", f.redactedExcerpt());
        }
        node.put("reason", f.reason());
        node.put("detector", f.detector());
        if (!f.relatedMessageIds().isEmpty()) {
            final ArrayNode related = node.putArray("relatedMessageIds");
            f.relatedMessageIds().forEach(related::add);
        }
        return node;
    }

    private static void appendFindings(final StringBuilder text, final List<Finding> findings) {
        int i = 1;
        for (final Finding f : findings) {
            text.append('\n').append(i++).append(". [").append(f.severity()).append("] ").append(f.ruleId());
            if (f.location() != null) {
                text.append(" at ").append(f.location());
            }
            if (f.start() >= 0) {
                text.append(' ').append(f.start()).append('-').append(f.end());
            }
            if (f.redactedExcerpt() != null) {
                text.append(" (").append(f.redactedExcerpt()).append(')');
            }
            text.append(": ").append(f.reason());
        }
    }

}
