package ucr.ac.cr.medivault.domain;

import jakarta.persistence.*;
import org.hibernate.annotations.Immutable;

import java.time.LocalDateTime;

/**
 * Registro de auditoria de seguridad inmutable (tabla AUDIT_LOGS).
 * No tiene setters y @Immutable hace que Hibernate ignore cualquier
 * intento de UPDATE una vez insertado.
 */
@Entity
@Immutable
@Table(name = "AUDIT_LOGS")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 50)
    private String username;

    @Column(name = "ip_origen", nullable = false, length = 45)
    private String ipOrigen;

    @Column(nullable = false, length = 50)
    private String accion;

    @Column(name = "recurso_solicitado", nullable = false, length = 255)
    private String recursoSolicitado;

    @Column(name = "codigo_estado", nullable = false)
    private Integer codigoEstado;

    @Column(name = "detalle_evento", length = 255)
    private String detalleEvento;

    @Column(name = "fecha_evento", insertable = false, updatable = false)
    private LocalDateTime fechaEvento;

    protected AuditLog() {}

    public AuditLog(String username, String ipOrigen, String accion,
                    String recursoSolicitado, int codigoEstado, String detalleEvento) {
        this.username = truncar(username, 50);
        this.ipOrigen = truncar(ipOrigen, 45);
        this.accion = truncar(accion, 50);
        this.recursoSolicitado = truncar(recursoSolicitado, 255);
        this.codigoEstado = codigoEstado;
        this.detalleEvento = truncar(detalleEvento, 255);
    }

    private static String truncar(String valor, int max) {
        if (valor == null) {
            return null;
        }
        return valor.length() <= max ? valor : valor.substring(0, max);
    }

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getIpOrigen() { return ipOrigen; }
    public String getAccion() { return accion; }
    public String getRecursoSolicitado() { return recursoSolicitado; }
    public Integer getCodigoEstado() { return codigoEstado; }
    public String getDetalleEvento() { return detalleEvento; }
    public LocalDateTime getFechaEvento() { return fechaEvento; }
}
