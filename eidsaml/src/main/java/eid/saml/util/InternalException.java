package eid.saml.util;

public class InternalException extends Exception {
    private static final long serialVersionUID = -7349369127890495417L;

    public InternalException(String errorMessage) {
        super(errorMessage);
    }

    public InternalException(String errorMessage, Exception exception) {
        super(errorMessage, exception);
    }

    public InternalException(Exception exception) {
        super(exception.getMessage(), exception);
    }
}
