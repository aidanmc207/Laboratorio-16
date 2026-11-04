package ucr.ac.cr.medivault.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ucr.ac.cr.medivault.business.AuthService;
import ucr.ac.cr.medivault.business.SecurityAuditorService;
import ucr.ac.cr.medivault.controller.dto.LoginRequestDto;
import ucr.ac.cr.medivault.controller.dto.LoginResponseDto;
import ucr.ac.cr.medivault.security.ClientIpResolver;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final SecurityAuditorService auditor;
    private final ClientIpResolver ipResolver;

    public AuthController(AuthService authService,
                          SecurityAuditorService auditor,
                          ClientIpResolver ipResolver) {
        this.authService = authService;
        this.auditor = auditor;
        this.ipResolver = ipResolver;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@Valid @RequestBody LoginRequestDto req,
                                                  HttpServletRequest request) {
        try {
            return ResponseEntity.ok(authService.autenticar(req));
        } catch (BadCredentialsException ex) {
            // Auditoria: cada credencial invalida queda registrada (401)
            auditor.registrarLoginFallido(
                    req.username(),
                    ipResolver.resolve(request),
                    request.getMethod() + " " + request.getRequestURI());
            throw ex;
        }
    }
}
