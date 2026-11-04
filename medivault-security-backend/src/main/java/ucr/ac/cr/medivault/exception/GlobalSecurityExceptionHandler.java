package ucr.ac.cr.medivault.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import ucr.ac.cr.medivault.business.SecurityAuditorService;
import ucr.ac.cr.medivault.security.ClientIpResolver;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * Manejador global RFC 7807 (ProblemDetail).
 * Ninguna respuesta expone stack traces, nombres de tablas, SQL ni
 * clases internas: el detalle tecnico solo se registra en el log del servidor.
 */
@RestControllerAdvice
public class GlobalSecurityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalSecurityExceptionHandler.class);
    private static final String BASE = "https://medivault.ucr.ac.cr/";

    private final SecurityAuditorService auditor;
    private final ClientIpResolver ipResolver;

    public GlobalSecurityExceptionHandler(SecurityAuditorService auditor,
                                          ClientIpResolver ipResolver) {
        this.auditor = auditor;
        this.ipResolver = ipResolver;
    }

    @ExceptionHandler(AccessDeniedSecurityException.class)
    public ProblemDetail handleAccessDenied(AccessDeniedSecurityException ex,
                                            HttpServletRequest request) {
        // Auditoria: cada intento IDOR/BOLA bloqueado queda registrado
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : null;
        auditor.registrarIntentoIdor(
                username,
                ipResolver.resolve(request),
                request.getMethod() + " " + request.getRequestURI(),
                ex.getMessage());

        return problem(HttpStatus.FORBIDDEN, ex.getMessage(),
                "Acceso Prohibido (IDOR / BOLA)", "forbidden");
    }

    @ExceptionHandler(org.springframework.security.access.AccessDeniedException.class)
    public ProblemDetail handleSpringAccessDenied(Exception ex) {
        return problem(HttpStatus.FORBIDDEN, "No posee permisos para este recurso.",
                "Acceso Prohibido", "forbidden");
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ProblemDetail handleNotFound(ResourceNotFoundException ex) {
        return problem(HttpStatus.NOT_FOUND, ex.getMessage(),
                "Recurso No Encontrado", "not-found");
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ProblemDetail handleNoResource(NoResourceFoundException ex) {
        return problem(HttpStatus.NOT_FOUND, "La ruta solicitada no existe.",
                "Recurso No Encontrado", "not-found");
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ProblemDetail handleBadCredentials(BadCredentialsException ex) {
        // Mensaje generico: no revela si fallo el usuario o la contrasena
        return problem(HttpStatus.UNAUTHORIZED, "Credenciales invalidas.",
                "Fallo de Autenticacion", "unauthorized");
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidation(MethodArgumentNotValidException ex) {
        ProblemDetail p = problem(HttpStatus.BAD_REQUEST, "Validacion de datos fallida.",
                "Error de Validacion", "bad-request");

        Map<String, String> errors = new HashMap<>();
        for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
            errors.put(fe.getField(), fe.getDefaultMessage());
        }
        p.setProperty("invalid_fields", errors);
        return p;
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ProblemDetail handleUnreadable(HttpMessageNotReadableException ex) {
        return problem(HttpStatus.BAD_REQUEST, "Cuerpo de la peticion mal formado.",
                "Error de Validacion", "bad-request");
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ProblemDetail handleTypeMismatch(MethodArgumentTypeMismatchException ex) {
        return problem(HttpStatus.BAD_REQUEST, "Parametro con formato invalido.",
                "Error de Validacion", "bad-request");
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleIllegalArgument(IllegalArgumentException ex) {
        return problem(HttpStatus.BAD_REQUEST, ex.getMessage(),
                "Error de Validacion", "bad-request");
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ProblemDetail handleDataIntegrity(DataIntegrityViolationException ex) {
        log.warn("Violacion de integridad de datos", ex);
        return problem(HttpStatus.CONFLICT, "El registro entra en conflicto con datos existentes.",
                "Conflicto de Datos", "conflict");
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ProblemDetail handleMethod(HttpRequestMethodNotSupportedException ex) {
        return problem(HttpStatus.METHOD_NOT_ALLOWED, "Metodo HTTP no soportado.",
                "Metodo No Permitido", "method-not-allowed");
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ProblemDetail handleMediaType(HttpMediaTypeNotSupportedException ex) {
        return problem(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "Tipo de contenido no soportado.",
                "Tipo de Contenido Invalido", "unsupported-media-type");
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleGeneric(Exception ex) {
        // El detalle real queda solo en el log interno
        log.error("Error no controlado", ex);
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "Error interno del servidor.",
                "Error Interno", "internal");
    }

    private static ProblemDetail problem(HttpStatus status, String detail,
                                         String title, String typeSuffix) {
        ProblemDetail p = ProblemDetail.forStatusAndDetail(status, detail);
        p.setTitle(title);
        p.setType(URI.create(BASE + typeSuffix));
        return p;
    }
}
