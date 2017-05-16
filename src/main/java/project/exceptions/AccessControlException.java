package project.exceptions;


public class AccessControlException extends Exception {

    private String message;

    public AccessControlException(String message) {
        this.message = message;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
