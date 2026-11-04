package ucr.ac.cr.medivault.business;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import ucr.ac.cr.medivault.config.AsyncConfig;
import ucr.ac.cr.medivault.controller.dto.AuditLogResponseDto;
import ucr.ac.cr.medivault.data.AuditLogRepository;
import ucr.ac.cr.medivault.domain.AuditLog;

import java.util.List;

/**
 * Servicio de auditoria de seguridad (Parte 3 - Requerimiento B).
 *
 * - Las escrituras son asincronas (@Async) y usan una transaccion propia
 *   (REQUIRES_NEW), por lo que el evento queda registrado aunque la
 *   operacion de negocio que lo provoco haga rollback.
 * - Nunca se registran datos clinicos: solo usuario, IP, accion, recurso,
 *   codigo HTTP y un detalle tecnico breve.
 */
@Service
public class SecurityAuditorService {

    public static final String IDOR_ATTEMPT_BLOCKED = "IDOR_ATTEMPT_BLOCKED";
    public static final String LOGIN_FAILED = "LOGIN_FAILED";

    private static final Logger log = LoggerFactory.getLogger(SecurityAuditorService.class);
    private static final int MAX_PAGE_SIZE = 100;

    private final AuditLogRepository auditRepo;

    public SecurityAuditorService(AuditLogRepository auditRepo) {
        this.auditRepo = auditRepo;
    }

    @Async(AsyncConfig.AUDIT_EXECUTOR)
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void registrarIntentoIdor(String username, String ip,
                                     String recurso, String detalle) {
        guardar(new AuditLog(username, ip, IDOR_ATTEMPT_BLOCKED, recurso, 403, detalle));
    }

    @Async(AsyncConfig.AUDIT_EXECUTOR)
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void registrarLoginFallido(String username, String ip, String recurso) {
        guardar(new AuditLog(username, ip, LOGIN_FAILED, recurso, 401,
                "Credenciales invalidas"));
    }

    @Transactional(readOnly = true)
    public List<AuditLogResponseDto> consultar(String accion, int page, int size) {
        PageRequest pr = PageRequest.of(Math.max(page, 0),
                Math.min(Math.max(size, 1), MAX_PAGE_SIZE));

        List<AuditLog> logs = (accion == null || accion.isBlank())
                ? auditRepo.findAllByOrderByIdDesc(pr)
                : auditRepo.findByAccionOrderByIdDesc(accion, pr);

        return logs.stream()
                .map(l -> new AuditLogResponseDto(
                        l.getId(), l.getUsername(), l.getIpOrigen(), l.getAccion(),
                        l.getRecursoSolicitado(), l.getCodigoEstado(),
                        l.getDetalleEvento(), l.getFechaEvento()))
                .toList();
    }

    private void guardar(AuditLog entry) {
        try {
            auditRepo.save(entry);
        } catch (RuntimeException ex) {
            // Un fallo de auditoria no debe tumbar la peticion original
            log.error("No se pudo registrar el evento de auditoria {}", entry.getAccion(), ex);
        }
    }
}
