package ucr.ac.cr.medivault.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import ucr.ac.cr.medivault.business.SecurityAuditorService;
import ucr.ac.cr.medivault.controller.dto.AuditLogResponseDto;

import java.util.List;

/**
 * Consulta de la bitacora de seguridad. Solo lectura y solo para el
 * administrador auditor; las respuestas no contienen datos clinicos.
 */
@RestController
@RequestMapping("/api/v1/auditoria")
public class AuditoriaController {

    private final SecurityAuditorService auditor;

    public AuditoriaController(SecurityAuditorService auditor) {
        this.auditor = auditor;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<AuditLogResponseDto>> listar(
            @RequestParam(required = false) String accion,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return ResponseEntity.ok(auditor.consultar(accion, page, size));
    }
}
