package ucr.ac.cr.medivault.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

public record ExpedienteRequestDto(
        @NotNull(message = "ID paciente obligatorio.")
        @Positive(message = "ID paciente positivo.")
        Long pacienteId,

        @NotBlank(message = "Codigo obligatorio.")
        @Pattern(regexp = "^EXP-\\d{4}-\\d{3,6}$", message = "Formato: EXP-YYYY-NNN.")
        String codigoExpediente,

        @NotBlank(message = "Diagnostico obligatorio.")
        @Size(min = 5, max = 255, message = "Diagnostico: 5 a 255 caracteres.")
        String diagnosticoPrincipal,

        @NotBlank(message = "Notas clinicas requeridas.")
        @Size(min = 10, max = 4000, message = "Notas: 10 a 4000 caracteres.")
        String notasClinicas,

        @NotBlank(message = "Confidencialidad requerida.")
        @Pattern(regexp = "^(BAJO|MEDIO|ALTO)$", message = "Valores: BAJO, MEDIO, ALTO.")
        String nivelConfidencialidad
) {}
