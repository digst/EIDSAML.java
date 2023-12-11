package eid.saml.util;

public class ExternalException extends Exception {
    private static final long serialVersionUID = -6358550455935444924L;

    public ExternalException(Exception exception) {
        super(exception.getMessage(), exception);
    }

    public ExternalException(String errorMessage) {
        super(errorMessage);
    }

    public ExternalException(String errorMessage, Exception exception) {
        super(errorMessage, exception);
    }
}
