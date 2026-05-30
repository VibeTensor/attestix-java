package io.vibetensor.attestix.json;

/** Thrown when JSON parsing fails. */
public class JsonException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public JsonException(String message) {
        super(message);
    }
}
