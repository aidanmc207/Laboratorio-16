package ucr.ac.cr.medivault.data;

import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.Repository;
import ucr.ac.cr.medivault.domain.AuditLog;

import java.util.List;

/**
 * Repositorio "append-only": extiende Repository (no JpaRepository) para
 * exponer unicamente insercion y lectura. No existen metodos de borrado
 * ni de actualizacion, lo que refuerza la inmutabilidad de la bitacora.
 */
public interface AuditLogRepository extends Repository<AuditLog, Long> {

    AuditLog save(AuditLog log);

    List<AuditLog> findAllByOrderByIdDesc(Pageable pageable);

    List<AuditLog> findByAccionOrderByIdDesc(String accion, Pageable pageable);

    long countByAccionAndIpOrigen(String accion, String ipOrigen);

    long countByAccionAndUsername(String accion, String username);
}
