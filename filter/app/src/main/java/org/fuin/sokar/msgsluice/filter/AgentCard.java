package org.fuin.sokar.msgsluice.filter;

import java.util.Objects;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * The filter's self-description in the shape of an A2A 1.0 {@code AgentCard}: its name and version, what it
 * reads and writes, its one skill, and the directory it reads from as a {@code file:} URI.
 *
 * <p>
 * Deliberately a self-description for file-based operation, not a card anybody could discover and call: the
 * filter binds no port and speaks no A2A protocol operation. It is printed by the program itself, from the
 * configuration it would run with, so it cannot drift from what that program is.
 */
public final class AgentCard {

    public static final String SKILL = "data-leak-check";

    private AgentCard() {
    }

    public static ObjectNode of(final ObjectMapper mapper, final FilterConfig config, final String version) {
        Objects.requireNonNull(config, "config");
        final ObjectNode card = mapper.createObjectNode();
        card.put("name", Answers.TOOL_NAME);
        card.put("description", "Checks the messages an agent sends out and lets through only plain English prose: "
                + "encoded data, inline files and structured payloads are refused, and the sender is answered with "
                + "the reasons. Reads A2A 1.0 messages from a directory; no network transport is offered.");
        card.put("version", version);
        final ObjectNode reads = card.putArray("supportedInterfaces").addObject();
        reads.put("url", config.incoming().toAbsolutePath().normalize().toUri().toString());
        reads.put("protocolBinding", "FILE");
        final ObjectNode capabilities = card.putObject("capabilities");
        capabilities.put("streaming", false);
        capabilities.put("pushNotifications", false);
        card.putArray("defaultInputModes").add("text/plain");
        // An answer carries a text part and a data part with the findings.
        card.putArray("defaultOutputModes").add("text/plain").add("application/json");
        final ObjectNode skill = card.putArray("skills").addObject();
        skill.put("id", SKILL);
        skill.put("name", "Data leak check");
        skill.put("description", "Refuses an outgoing message that carries encoded data, an inline file or "
                + "structured data, and names every rule it broke. " + (config.blocking()
                        ? "This instance refuses."
                        : "This instance only reports: until blocking is switched on, it refuses nothing for "
                                + "its content."));
        skill.putArray("tags").add("egress").add("data-loss-prevention").add("a2a");
        skill.putArray("inputModes").add("text/plain");
        skill.putArray("outputModes").add("text/plain").add("application/json");
        return card;
    }

}
