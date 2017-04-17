package project.exceptions;

public class VersionNotAllowedException extends Exception {

    private String message;

    public VersionNotAllowedException(String message) {
        this.message = message;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
