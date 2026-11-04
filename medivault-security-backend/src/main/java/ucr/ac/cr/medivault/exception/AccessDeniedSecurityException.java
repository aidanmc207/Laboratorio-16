package ucr.ac.cr.medivault.exception;

public class AccessDeniedSecurityException extends RuntimeException {
    public AccessDeniedSecurityException(String msg) {
        super(msg);
    }
}
