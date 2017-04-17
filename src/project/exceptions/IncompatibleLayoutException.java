package project.exceptions;

public class IncompatibleLayoutException extends Exception {

    private String message;

    public IncompatibleLayoutException(String message) {
        this.message = message;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
