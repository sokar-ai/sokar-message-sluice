package org.fuin.sokar.msgsluice.filter;

/** The configuration cannot be used. The filter does not start: it fails closed and loud. */
public final class ConfigException extends Exception {

    private static final long serialVersionUID = 1L;

    public ConfigException(final String message) {
        super(message);
    }

}
