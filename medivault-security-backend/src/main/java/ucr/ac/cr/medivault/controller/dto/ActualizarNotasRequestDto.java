package ucr.ac.cr.medivault.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * DTO de la Parte 2: reemplaza el @RequestBody String sin validacion
 * del endpoint vulnerable de actualizacion de notas.
 */
public record ActualizarNotasRequestDto(
        @NotBlank(message = "Notas clinicas requeridas.")
        @Size(min = 10, max = 4000, message = "Notas: 10 a 4000 caracteres.")
        String notasClinicas
) {}
