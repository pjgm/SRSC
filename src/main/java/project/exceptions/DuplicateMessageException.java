package project.exceptions;

public class DuplicateMessageException extends Exception {

    private String message;

    public DuplicateMessageException(String message) {
        this.message = message;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
