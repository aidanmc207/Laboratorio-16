package ucr.ac.cr.medivault.domain;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "EXPEDIENTES_MEDICOS")
public class ExpedienteMedico {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "paciente_id", nullable = false)
    private Usuario paciente;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "medico_asignado_id", nullable = false)
    private Usuario medicoAsignado;

    @Column(name = "codigo_expediente", nullable = false, unique = true, length = 30)
    private String codigoExpediente;

    @Column(name = "diagnostico_principal", nullable = false)
    private String diagnosticoPrincipal;

    @Column(name = "notas_clinicas", nullable = false, columnDefinition = "TEXT")
    private String notasClinicas;

    @Column(name = "nivel_confidencialidad", nullable = false, length = 20)
    private String nivelConfidencialidad;

    @Column(name = "fecha_registro", insertable = false, updatable = false)
    private LocalDateTime fechaRegistro;

    public ExpedienteMedico() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Usuario getPaciente() { return paciente; }
    public void setPaciente(Usuario paciente) { this.paciente = paciente; }

    public Usuario getMedicoAsignado() { return medicoAsignado; }
    public void setMedicoAsignado(Usuario m) { this.medicoAsignado = m; }

    public String getCodigoExpediente() { return codigoExpediente; }
    public void setCodigoExpediente(String c) { this.codigoExpediente = c; }

    public String getDiagnosticoPrincipal() { return diagnosticoPrincipal; }
    public void setDiagnosticoPrincipal(String d) { this.diagnosticoPrincipal = d; }

    public String getNotasClinicas() { return notasClinicas; }
    public void setNotasClinicas(String notas) { this.notasClinicas = notas; }

    public String getNivelConfidencialidad() { return nivelConfidencialidad; }
    public void setNivelConfidencialidad(String n) { this.nivelConfidencialidad = n; }

    public LocalDateTime getFechaRegistro() { return fechaRegistro; }
}
