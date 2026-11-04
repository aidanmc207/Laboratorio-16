package ucr.ac.cr.medivault.controller.dto;

import java.time.LocalDateTime;

public record AuditLogResponseDto(
        Long id,
        String username,
        String ipOrigen,
        String accion,
        String recursoSolicitado,
        Integer codigoEstado,
        String detalleEvento,
        LocalDateTime fechaEvento
) {}
