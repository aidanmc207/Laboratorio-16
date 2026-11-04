package ucr.ac.cr.medivault.controller.dto;

public record LoginResponseDto(
        String token,
        String tokenType,
        long expiresInMs,
        String username,
        String rol
) {}
