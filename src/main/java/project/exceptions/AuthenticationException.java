package project.exceptions;

public class AuthenticationException extends Exception {

    private String message;

    public AuthenticationException(String message) {
        this.message = message;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
