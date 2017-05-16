package project.exceptions;

public class CorruptedMessageException extends Exception {

    private String message;

    public CorruptedMessageException(String message) {
        this.message = message;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
