package net.shibboleth.idp.oidc;

public class OIDCException extends RuntimeException {

    public OIDCException() {
    }

    public OIDCException(final String message) {
        super(message);
    }

    public OIDCException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public OIDCException(final Throwable cause) {
        super(cause);
    }

    public OIDCException(final String message, final Throwable cause, final boolean enableSuppression,
                         final boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
