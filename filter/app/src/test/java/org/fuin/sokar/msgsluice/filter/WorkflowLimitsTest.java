package org.fuin.sokar.msgsluice.filter;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

/**
 * A job without {@code timeout-minutes} runs for GitHub's six hours on a slow runner. Read as lines, the way the
 * workflows are written: a job is a two-space key under {@code jobs:}, its limit a four-space key.
 */
class WorkflowLimitsTest {

    private static final Path WORKFLOWS = Path.of("..", "..", ".github", "workflows");

    private static final Pattern JOB = Pattern.compile("^  ([A-Za-z0-9_-]+):\\s*$");

    private static final Pattern LIMIT = Pattern.compile("^    timeout-minutes: [1-9][0-9]*\\s*$");

    @Test
    void everyJobHasATimeLimit() throws IOException {
        final List<String> jobs = new ArrayList<>();
        final List<String> unlimited = new ArrayList<>();
        for (final Path workflow : workflows()) {
            boolean inJobs = false;
            String job = null;
            boolean limited = false;
            for (final String line : Files.readAllLines(workflow)) {
                if (!line.startsWith(" ") && !line.isBlank() && !line.startsWith("#")) {
                    inJobs = line.equals("jobs:");
                }
                if (!inJobs) {
                    continue;
                }
                final Matcher m = JOB.matcher(line);
                if (m.matches()) {
                    if (job != null && !limited) {
                        unlimited.add(job);
                    }
                    job = workflow.getFileName() + " " + m.group(1);
                    jobs.add(job);
                    limited = false;
                } else if (LIMIT.matcher(line).matches()) {
                    limited = true;
                }
            }
            if (job != null && !limited) {
                unlimited.add(job);
            }
        }

        // A wrong root finds no job and would pass: the build job must be among them.
        assertThat(jobs).contains("build.yml build");
        assertThat(unlimited).as("jobs without timeout-minutes").isEmpty();
    }

    private static List<Path> workflows() throws IOException {
        assertThat(WORKFLOWS).isDirectory();
        try (Stream<Path> files = Files.list(WORKFLOWS)) {
            return files.filter(f -> f.getFileName().toString().endsWith(".yml")).sorted().toList();
        }
    }

}
