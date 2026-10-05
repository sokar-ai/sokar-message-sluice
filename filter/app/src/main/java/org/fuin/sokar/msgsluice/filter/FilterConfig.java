package org.fuin.sokar.msgsluice.filter;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;

import org.fuin.sokar.msgsluice.filter.a2a.CheckConfig;
import org.fuin.sokar.msgsluice.filter.decision.DecisionConfig;
import org.fuin.sokar.msgsluice.filter.decision.Redactor;

/**
 * Everything one filter instance needs. The paths are given, never derived: where a message goes is a policy
 * decision, and those belong to the host.
 *
 * @param incoming          what to read
 * @param accepted          where an accepted message goes; never a transport's queue
 * @param corpus            what this task already sent, for idempotence and, later, correlation
 * @param feedback          where receipts and rejections are written
 * @param rejected          the refused originals; holds clear-text secrets, so {@code 0700}
 * @param error             files that could not be processed; {@code 0700} for the same reason
 * @param lock              the lock file that keeps a second instance out
 * @param check             the envelope's limits
 * @param decision          how findings become a verdict
 * @param redaction         how an excerpt is masked
 * @param blocking          {@code false} until this directory has been calibrated: it then reports rather than refuses
 * @param receiptOnApproval whether an accepted message gets a receipt
 * @param stabilityDelay    how long a file's size must stay unchanged before it is read
 * @param watchInterval     how often watch mode looks even when no change was signalled
 */
public record FilterConfig(Path incoming, Path accepted, Path corpus, Path feedback, Path rejected, Path error,
        Path lock, CheckConfig check, DecisionConfig decision, Redactor.Mode redaction, boolean blocking,
        boolean receiptOnApproval, Duration stabilityDelay, Duration watchInterval) {

    public FilterConfig {
        Objects.requireNonNull(incoming, "incoming");
        Objects.requireNonNull(accepted, "accepted");
        Objects.requireNonNull(corpus, "corpus");
        Objects.requireNonNull(feedback, "feedback");
        Objects.requireNonNull(rejected, "rejected");
        Objects.requireNonNull(error, "error");
        Objects.requireNonNull(lock, "lock");
        Objects.requireNonNull(check, "check");
        Objects.requireNonNull(decision, "decision");
        Objects.requireNonNull(redaction, "redaction");
        Objects.requireNonNull(stabilityDelay, "stabilityDelay");
        Objects.requireNonNull(watchInterval, "watchInterval");
    }

}
