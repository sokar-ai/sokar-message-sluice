package org.fuin.sokar.msgsluice.filter.decision;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class RedactorTest {

    @Test
    void partialShowsFourCharactersOfALongMatchAndNoneOfAShortOne() {
        final Redactor redactor = new Redactor(Redactor.Mode.PARTIAL);
        assertThat(redactor.redact("key AKIAIOSFODNN7EXAMPLE end", 4, 24, "CLOUD_KEY")).isEqualTo("AKIA************");
        assertThat(redactor.redact("my password is hunter2", 15, 22, "PASSWORD")).isEqualTo("*******");
    }

    @Test
    void fullAndHashShowNothingOfTheMatch() {
        assertThat(new Redactor(Redactor.Mode.FULL).redact("abcdefgh", 0, 8, "X")).isEqualTo("[REDACTED:X]");
        assertThat(new Redactor(Redactor.Mode.HASH).redact("abcdefgh", 0, 8, "X")).startsWith("sha256:")
                .doesNotContain("abcd");
    }

    @Test
    void offsetsOutsideTheTextCannotBeRedacted() {
        final Redactor redactor = new Redactor(Redactor.Mode.PARTIAL);
        assertThatThrownBy(() -> redactor.redact("abc", 1, 9, "X")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> redactor.redact("abc", 2, 2, "X")).isInstanceOf(IllegalArgumentException.class);
    }

}
