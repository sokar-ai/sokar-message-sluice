package org.fuin.sokar.msgsluice.filter.a2a;

import org.jspecify.annotations.Nullable;

/**
 * The ids an answer refers back to. Each is present only when it passed the id check, so an answer never
 * echoes a malformed id - which could be a payload wearing an id's name.
 *
 * @param messageId the message's id, or {@code null} for a task or an invalid id
 * @param contextId the context, if valid
 * @param taskId    the task, if valid
 */
public record MessageFacts(@Nullable String messageId, @Nullable String contextId, @Nullable String taskId) {

    public static final MessageFacts NONE = new MessageFacts(null, null, null);

}
