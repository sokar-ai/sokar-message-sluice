package org.fuin.sokar.msgsluice.filter.a2a;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

import org.fuin.sokar.msgsluice.filter.decision.Finding;
import org.fuin.sokar.msgsluice.filter.decision.Severity;
import org.fuin.sokar.msgsluice.filter.detect.TextUnderCheck;
import org.jspecify.annotations.Nullable;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Stage A: the structure of an A2A 1.0 message or task, judged on structure alone. Cheap and decisive - a
 * payload part is refused before a character of text is analyzed. Every string it does not validate
 * structurally is handed on as text for the detectors, so there is no field a payload can hide in unseen.
 */
public final class EnvelopeCheck {

    /** Every rule id stage A can report; a configuration naming one of these weighs it but cannot disable it. */
    public static final Set<String> RULE_IDS = Set.of("ENVELOPE/UNEXPECTED_ROLE", "ENVELOPE/TOO_MANY_PARTS",
            "ENVELOPE/AMBIGUOUS_PART", "ENVELOPE/EMPTY_PART", "ENVELOPE/RAW_PART_NOT_ALLOWED",
            "ENVELOPE/URL_PART_NOT_ALLOWED", "ENVELOPE/DATA_PART_NOT_ALLOWED", "ENVELOPE/TEXT_TOO_LONG",
            "ENVELOPE/FILENAME_ON_TEXT_PART", "ENVELOPE/UNEXPECTED_MEDIA_TYPE", "ENVELOPE/PEER_NAME_MALFORMED",
            "ENVELOPE/METADATA_TOO_DEEP", "ENVELOPE/METADATA_TOO_LARGE", "ENVELOPE/EXTENSION_MALFORMED",
            "ENVELOPE/UNKNOWN_FIELD", "ENVELOPE/ID_MALFORMED", "ENVELOPE/DUPLICATE_MESSAGE_ID",
            "ENVELOPE/TOO_MANY_REFERENCES");

    private static final Set<String> MESSAGE_FIELDS = Set.of("messageId", "contextId", "taskId", "role", "parts",
            "metadata", "extensions", "referenceTaskIds");

    private static final Set<String> PART_FIELDS = Set.of("text", "raw", "url", "data", "metadata", "filename",
            "mediaType");

    private static final Set<String> TASK_FIELDS = Set.of("id", "contextId", "status", "artifacts", "history",
            "metadata");

    private static final Set<String> STATUS_FIELDS = Set.of("state", "message", "timestamp");

    private static final Set<String> ARTIFACT_FIELDS = Set.of("artifactId", "name", "description", "parts",
            "metadata", "extensions");

    private static final Set<String> ROLES = Set.of("ROLE_UNSPECIFIED", "ROLE_USER", "ROLE_AGENT");

    private static final Set<String> CONTENT_FIELDS = Set.of("text", "raw", "url", "data");

    private static final Pattern ID = Pattern.compile("[A-Za-z0-9._:-]+");

    /** A peer is named by its principal in the project's machine-signers, which is often user@host. */
    private static final Pattern PEER = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._@-]*");

    private static final Pattern URI = Pattern.compile("[A-Za-z][A-Za-z0-9+.-]*:\\S+");

    /** A field name shown in clear only when it is short and plain; anything else could be a payload. */
    private static final Pattern PRINTABLE_NAME = Pattern.compile("[A-Za-z][A-Za-z0-9_-]{0,31}");

    private static final Pattern BINARY_EXTENSION = Pattern.compile(
            ".*\\.(zip|gz|tgz|bz2|xz|7z|rar|tar|jar|png|jpe?g|gif|bmp|webp|pdf|docx?|xlsx?|pptx?|p12|pfx|der|key|"
                    + "exe|dll|so|bin|iso|dmg)$",
            Pattern.CASE_INSENSITIVE);

    private static final Set<String> BLOCKING_MEDIA_TYPES = Set.of("application/octet-stream", "application/zip",
            "application/json");

    private final CheckConfig config;

    public EnvelopeCheck(final CheckConfig config) {
        this.config = Objects.requireNonNull(config, "config");
    }

    /**
     * @throws Unprocessable when the tree is not an A2A 1.0 message or task at all
     */
    public EnvelopeResult check(final JsonNode root) throws Unprocessable {
        if (!root.isObject()) {
            throw notA2a();
        }
        rejectVersion03(root);
        final boolean task = root.has("status");
        final boolean message = root.has("parts") && root.has("role");
        if (task == message) {
            throw notA2a();
        }
        final Walk walk = new Walk();
        final MessageFacts facts;
        if (message) {
            facts = walk.message(root, "", true);
        } else {
            facts = walk.task(root);
        }
        return new EnvelopeResult(facts, walk.findings, walk.texts, walk.shownKeys);
    }

    /** Refused, never converted: a conversion would have to guess how {@code file.bytes} maps onto {@code raw}. */
    private static void rejectVersion03(final JsonNode node) throws Unprocessable {
        if (node.isObject()) {
            if (node.has("kind")) {
                throw version03();
            }
            final JsonNode role = node.get("role");
            if (role != null && role.isTextual() && Set.of("agent", "user").contains(role.asText())) {
                throw version03();
            }
            final JsonNode status = node.get("status");
            if (status != null && status.isObject() && status.path("state").isTextual()
                    && !status.path("state").asText().startsWith("TASK_STATE_")
                    && status.path("state").asText().equals(status.path("state").asText().toLowerCase(Locale.ROOT))) {
                throw version03();
            }
            for (final Iterator<String> it = node.fieldNames(); it.hasNext();) {
                final String name = it.next();
                // Metadata is free-form: a "kind" key there is somebody's data, not the 0.3 discriminator.
                if (!name.equals("metadata") && !name.equals("data")) {
                    rejectVersion03(node.get(name));
                }
            }
        } else if (node.isArray()) {
            for (final JsonNode element : node) {
                rejectVersion03(element);
            }
        }
    }

    private static Unprocessable version03() {
        return new Unprocessable("UNPROCESSABLE/UNSUPPORTED_PROTOCOL_VERSION",
                "The file is recognizably an A2A 0.3 message (a 'kind' field or a lower-case enum). Only A2A 1.0 "
                        + "is accepted, and nothing is converted.");
    }

    private static Unprocessable notA2a() {
        return new Unprocessable("UNPROCESSABLE/NOT_AN_A2A_MESSAGE",
                "The file is neither an A2A 1.0 message (with 'parts' and 'role') nor a task (with 'status').");
    }

    private static Unprocessable schema(final String location, final String what) {
        return new Unprocessable("UNPROCESSABLE/SCHEMA_VIOLATION",
                "The field at " + location + " " + what + ", which A2A 1.0 does not allow.");
    }

    /** What one check found, collected while walking the tree. */
    private final class Walk {

        private final List<Finding> findings = new ArrayList<>();

        private final List<TextUnderCheck> texts = new ArrayList<>();

        /** Every location that names a key in clear, and the same location naming it by position. */
        private final Map<String, String> shownKeys = new java.util.LinkedHashMap<>();

        private MessageFacts message(final JsonNode msg, final String path, final boolean outer)
                throws Unprocessable {
            if (!msg.isObject()) {
                throw schema(where(path, "message"), "is not an object");
            }
            unknownFields(msg, MESSAGE_FIELDS, path);

            final String messageId = id(msg, "messageId", path, true);
            final String contextId = id(msg, "contextId", path, false);
            final String taskId = id(msg, "taskId", path, false);

            final JsonNode role = msg.get("role");
            // A role A2A does not have is a free-form string no detector would see, so it is never "any role".
            if (role == null || !role.isTextual() || !ROLES.contains(role.asText())) {
                throw schema(path + "role", "is missing or not one of " + new java.util.TreeSet<>(ROLES));
            } else if (outer && !config.allowedRoles().isEmpty() && !config.allowedRoles().contains(role.asText())) {
                unexpectedRole();
            }

            parts(msg.get("parts"), path + "parts", true);
            metadata(msg.get("metadata"), path + "metadata");
            extensions(msg.get("extensions"), path + "extensions");
            final JsonNode refs = msg.get("referenceTaskIds");
            if (refs != null) {
                if (!refs.isArray()) {
                    throw schema(path + "referenceTaskIds", "is not an array");
                }
                if (refs.size() > config.maxReferenceTaskIds()) {
                    // Each id is short and plain; thousands of them are a channel all the same.
                    findings.add(Finding.envelope("ENVELOPE/TOO_MANY_REFERENCES", Severity.BLOCKING,
                            path + "referenceTaskIds", -1, "The message references " + refs.size()
                                    + " tasks; at most " + config.maxReferenceTaskIds() + " are allowed."));
                }
                int i = 0;
                for (final JsonNode ref : refs) {
                    idValue(ref, path + "referenceTaskIds[" + i++ + "]");
                }
            }
            return new MessageFacts(messageId, contextId, taskId);
        }

        private void unexpectedRole() {
            // Worded technically on purpose: an unexpected role means a miswired pipeline, not a content
            // violation, and must not read like one.
            findings.add(Finding.envelope("ENVELOPE/UNEXPECTED_ROLE", Severity.BLOCKING, "role", -1,
                    "The outer message must have one of the roles " + String.join(", ",
                            new java.util.TreeSet<>(config.allowedRoles())) + ". Any other role means the "
                            + "pipeline is wired wrongly, so nothing in it is checked for content."));
        }

        private MessageFacts task(final JsonNode task) throws Unprocessable {
            unknownFields(task, TASK_FIELDS, "");
            final String taskId = id(task, "id", "", true);
            final String contextId = id(task, "contextId", "", false);

            final JsonNode status = task.get("status");
            if (!status.isObject()) {
                throw schema("status", "is not an object");
            }
            unknownFields(status, STATUS_FIELDS, "status.");
            final JsonNode state = status.get("state");
            if (state == null || !state.isTextual() || !state.asText().startsWith("TASK_STATE_")) {
                throw schema("status.state", "is missing or not a TASK_STATE_ value");
            }
            if (status.has("message")) {
                message(status.get("message"), "status.message.", false);
            }
            final JsonNode timestamp = status.get("timestamp");
            if (timestamp != null) {
                text(timestamp, "status.timestamp", -1);
            }

            final JsonNode artifacts = task.get("artifacts");
            if (artifacts != null) {
                if (!artifacts.isArray()) {
                    throw schema("artifacts", "is not an array");
                }
                int i = 0;
                for (final JsonNode artifact : artifacts) {
                    artifact(artifact, "artifacts[" + i++ + "].");
                }
            }
            final JsonNode history = task.get("history");
            if (history != null) {
                if (!history.isArray()) {
                    throw schema("history", "is not an array");
                }
                int i = 0;
                for (final JsonNode msg : history) {
                    // A task's history may legitimately hold ROLE_USER messages: no role check inside.
                    message(msg, "history[" + i++ + "].", false);
                }
            }
            metadata(task.get("metadata"), "metadata");
            return new MessageFacts(null, contextId, taskId);
        }

        private void artifact(final JsonNode artifact, final String path) throws Unprocessable {
            if (!artifact.isObject()) {
                throw schema(where(path, "artifact"), "is not an object");
            }
            unknownFields(artifact, ARTIFACT_FIELDS, path);
            id(artifact, "artifactId", path, true);
            for (final String field : List.of("name", "description")) {
                final JsonNode value = artifact.get(field);
                if (value != null) {
                    text(value, path + field, -1);
                }
            }
            parts(artifact.get("parts"), path + "parts", true);
            metadata(artifact.get("metadata"), path + "metadata");
            extensions(artifact.get("extensions"), path + "extensions");
        }

        private void parts(final @Nullable JsonNode parts, final String path, final boolean required)
                throws Unprocessable {
            if (parts == null) {
                if (required) {
                    throw schema(path, "is missing");
                }
                return;
            }
            if (!parts.isArray()) {
                throw schema(path, "is not an array");
            }
            if (parts.size() > config.maxParts()) {
                findings.add(Finding.envelope("ENVELOPE/TOO_MANY_PARTS", Severity.BLOCKING, path, -1,
                        "The message has " + parts.size() + " parts; at most " + config.maxParts() + " are allowed."));
            }
            for (int i = 0; i < parts.size(); i++) {
                part(parts.get(i), path + "[" + i + "]", i);
            }
        }

        private void part(final JsonNode part, final String path, final int index) throws Unprocessable {
            if (!part.isObject()) {
                throw schema(path, "is not an object");
            }
            unknownFields(part, PART_FIELDS, path + ".");
            final List<String> content = new ArrayList<>();
            for (final String field : CONTENT_FIELDS) {
                if (part.has(field) && !part.get(field).isNull()) {
                    content.add(field);
                }
            }
            if (content.size() > 1) {
                // The oneof is not enforced by JSON; a reader that takes only the first field is the bypass.
                findings.add(Finding.envelope("ENVELOPE/AMBIGUOUS_PART", Severity.BLOCKING, path, index,
                        "The part sets " + String.join(" and ", content)
                                + ". A part carries exactly one content field."));
            } else if (content.isEmpty()) {
                findings.add(Finding.envelope("ENVELOPE/EMPTY_PART", Severity.SUSPICIOUS, path, index,
                        "The part carries no content field."));
            }
            if (content.contains("raw")) {
                findings.add(Finding.envelope("ENVELOPE/RAW_PART_NOT_ALLOWED", Severity.BLOCKING, path + ".raw",
                        index, "The part carries inline binary content. Only plain English text may be sent."));
            }
            if (content.contains("url")) {
                findings.add(Finding.envelope("ENVELOPE/URL_PART_NOT_ALLOWED", config.urlPartSeverity(),
                        path + ".url", index,
                        "The part is a reference to external content. Only plain English text may be sent."));
                text(part.get("url"), path + ".url", index);
            }
            if (content.contains("data")) {
                findings.add(Finding.envelope("ENVELOPE/DATA_PART_NOT_ALLOWED", Severity.BLOCKING, path + ".data",
                        index, "The part carries structured data. Only plain English text may be sent."));
            }
            final boolean isText = content.contains("text");
            if (isText) {
                final JsonNode text = part.get("text");
                if (!text.isTextual()) {
                    throw schema(path + ".text", "is not a string");
                }
                if (text.asText().length() > config.maxTextLengthPerPart()) {
                    findings.add(Finding.envelope("ENVELOPE/TEXT_TOO_LONG", Severity.BLOCKING, path + ".text", index,
                            "The text has " + text.asText().length() + " characters; at most "
                                    + config.maxTextLengthPerPart() + " are allowed."));
                }
                texts.add(new TextUnderCheck(path + ".text", index, text.asText()));
            }
            final JsonNode filename = part.get("filename");
            if (filename != null) {
                if (!filename.isTextual()) {
                    throw schema(path + ".filename", "is not a string");
                }
                if (isText) {
                    final boolean binary = BINARY_EXTENSION.matcher(filename.asText()).matches();
                    findings.add(Finding.envelope("ENVELOPE/FILENAME_ON_TEXT_PART",
                            binary ? Severity.BLOCKING : Severity.SUSPICIOUS, path + ".filename", index,
                            binary ? "A text part names a binary file, which is a file transfer in disguise."
                                    : "A text part names a file."));
                }
                texts.add(new TextUnderCheck(path + ".filename", index, filename.asText()));
            }
            final JsonNode mediaType = part.get("mediaType");
            if (mediaType != null) {
                if (!mediaType.isTextual()) {
                    throw schema(path + ".mediaType", "is not a string");
                }
                final String type = mediaType.asText().toLowerCase(Locale.ROOT).split(";", 2)[0].strip();
                if (isText && !type.isEmpty() && !type.equals("text/plain")) {
                    final boolean blocking = BLOCKING_MEDIA_TYPES.contains(type);
                    findings.add(Finding.envelope("ENVELOPE/UNEXPECTED_MEDIA_TYPE",
                            blocking ? Severity.BLOCKING : Severity.SUSPICIOUS, path + ".mediaType", index,
                            "A text part is expected to be text/plain."));
                }
                texts.add(new TextUnderCheck(path + ".mediaType", index, mediaType.asText()));
            }
            metadata(part.get("metadata"), path + ".metadata");
        }

        private void metadata(final @Nullable JsonNode metadata, final String path) throws Unprocessable {
            if (metadata == null || metadata.isNull()) {
                return;
            }
            if (!metadata.isObject()) {
                throw schema(path, "is not an object");
            }
            for (final String peer : List.of("to", "from")) {
                final JsonNode name = metadata.get(peer);
                if (name != null && (!name.isTextual() || name.asText().length() > config.maxIdLength()
                        || !PEER.matcher(name.asText()).matches())) {
                    // A peer name is checked as a name and never resolved: who a peer is belongs to the host.
                    findings.add(Finding.envelope("ENVELOPE/PEER_NAME_MALFORMED", Severity.BLOCKING,
                            path + "." + peer, -1, "The peer name is not a plain name of at most "
                                    + config.maxIdLength() + " letters, digits, '.', '_', '@' or '-'."));
                }
            }
            freeForm(metadata, path, "metadata");
        }

        /**
         * Free-form JSON - metadata, or a field A2A does not define - held to the metadata's depth and size, with
         * every key and every scalar handed to the detectors, however deep.
         */
        private void freeForm(final JsonNode value, final String path, final String what) {
            final int[] chars = {0};
            final boolean[] tooDeep = {false};
            walkValue(value, path, 1, chars, tooDeep);
            if (tooDeep[0]) {
                findings.add(Finding.envelope("ENVELOPE/METADATA_TOO_DEEP", Severity.BLOCKING, path, -1,
                        "The " + what + " is nested deeper than " + config.maxMetadataDepth() + " levels."));
            }
            if (chars[0] > config.maxMetadataChars()) {
                findings.add(Finding.envelope("ENVELOPE/METADATA_TOO_LARGE", Severity.BLOCKING, path, -1,
                        "The " + what + " holds " + chars[0] + " characters; at most " + config.maxMetadataChars()
                                + " are allowed."));
            }
        }

        /**
         * Every key and every scalar goes to the detectors: free-form JSON is an ideal hiding place. The walk goes
         * on below the depth limit, which the reader's nesting limit bounds, so nothing deep goes unread.
         */
        private void walkValue(final JsonNode node, final String path, final int depth, final int[] chars,
                final boolean[] tooDeep) {
            if (depth > config.maxMetadataDepth()) {
                tooDeep[0] = true;
            }
            if (node.isObject()) {
                int i = 0;
                for (final Iterator<Map.Entry<String, JsonNode>> it = node.fields(); it.hasNext(); i++) {
                    final Map.Entry<String, JsonNode> field = it.next();
                    final String child = path + "." + name(path + ".", field.getKey(), i);
                    chars[0] += field.getKey().length();
                    texts.add(new TextUnderCheck(child + "(key)", -1, field.getKey()));
                    walkValue(field.getValue(), child, depth + 1, chars, tooDeep);
                }
            } else if (node.isArray()) {
                for (int i = 0; i < node.size(); i++) {
                    walkValue(node.get(i), path + "[" + i + "]", depth + 1, chars, tooDeep);
                }
            } else if (!node.isNull()) {
                // Numbers too: three hundred digits are a payload whatever their JSON type.
                final String value = node.asText();
                chars[0] += value.length();
                texts.add(new TextUnderCheck(path, -1, value));
            }
        }

        private void extensions(final @Nullable JsonNode extensions, final String path) throws Unprocessable {
            if (extensions == null) {
                return;
            }
            if (!extensions.isArray()) {
                throw schema(path, "is not an array");
            }
            for (int i = 0; i < extensions.size(); i++) {
                final JsonNode uri = extensions.get(i);
                final String location = path + "[" + i + "]";
                if (!uri.isTextual()) {
                    throw schema(location, "is not a string");
                }
                if (uri.asText().length() > 256 || !URI.matcher(uri.asText()).matches()) {
                    findings.add(Finding.envelope("ENVELOPE/EXTENSION_MALFORMED", Severity.SUSPICIOUS, location, -1,
                            "An extension is expected to be a URI of at most 256 characters."));
                }
                texts.add(new TextUnderCheck(location, -1, uri.asText()));
            }
        }

        private void unknownFields(final JsonNode node, final Set<String> known, final String path) {
            int i = 0;
            for (final Iterator<Map.Entry<String, JsonNode>> it = node.fields(); it.hasNext(); i++) {
                final Map.Entry<String, JsonNode> field = it.next();
                if (!known.contains(field.getKey())) {
                    final String location = path + name(path, field.getKey(), i);
                    // A schema that ignores what it does not know is a smuggling channel.
                    findings.add(Finding.envelope("ENVELOPE/UNKNOWN_FIELD", Severity.SUSPICIOUS, location, -1,
                            "The field is not part of A2A 1.0."));
                    texts.add(new TextUnderCheck(location + "(key)", -1, field.getKey()));
                    freeForm(field.getValue(), location, "field");
                }
            }
        }

        private @Nullable String id(final JsonNode node, final String field, final String path, final boolean required)
                throws Unprocessable {
            final JsonNode value = node.get(field);
            if (value == null || value.isNull()) {
                if (required) {
                    throw schema(path + field, "is missing");
                }
                return null;
            }
            return idValue(value, path + field);
        }

        private @Nullable String idValue(final JsonNode value, final String location) throws Unprocessable {
            if (!value.isTextual()) {
                throw schema(location, "is not a string");
            }
            final String id = value.asText();
            // An id's alphabet is base64url's and hex's, so its shape says nothing about what it carries.
            texts.add(new TextUnderCheck(location, -1, id));
            if (id.isEmpty() || id.length() > config.maxIdLength() || !ID.matcher(id).matches()) {
                // A 4 KB base64 "id" is not an id.
                findings.add(Finding.envelope("ENVELOPE/ID_MALFORMED", Severity.BLOCKING, location, -1,
                        "An id must be 1 to " + config.maxIdLength() + " letters, digits, '.', '_', ':' or '-'."));
                return null;
            }
            return id;
        }

        /** A key's name in a location, remembering its positional form in case a rule matches the key. */
        private String name(final String prefix, final String key, final int index) {
            final String shown = printable(key, index);
            if (shown.equals(key)) {
                shownKeys.put(prefix + shown, prefix + "#" + index);
            }
            return shown;
        }

        private void text(final JsonNode value, final String location, final int partIndex) throws Unprocessable {
            if (!value.isTextual()) {
                throw schema(location, "is not a string");
            }
            texts.add(new TextUnderCheck(location, partIndex, value.asText()));
        }

    }

    /**
     * A field name as it may appear in a location: itself if short and plain, otherwise only its position. A plain
     * name a rule matches is replaced by its position too, once the detectors have run - see
     * {@link EnvelopeResult#withKeysHidden}.
     */
    static String printable(final String name, final int index) {
        return PRINTABLE_NAME.matcher(name).matches() ? name : "#" + index;
    }

    private static String where(final String path, final String fallback) {
        return path.isEmpty() ? fallback : path.substring(0, path.length() - 1);
    }

}
