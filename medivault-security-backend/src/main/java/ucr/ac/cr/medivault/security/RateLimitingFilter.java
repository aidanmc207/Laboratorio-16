package ucr.ac.cr.medivault.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;

/**
 * Filtro de Rate Limiting (algoritmo Token Bucket con Bucket4j).
 *
 * PENDIENTE (Parte 3 - Requerimiento A): reemplazar los buckets globales
 * por un ConcurrentHashMap de buckets por direccion IP del cliente
 * (X-Forwarded-For o request.getRemoteAddr()), con un limite de
 * 5 intentos de login por minuto por IP.
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    // Login: 10 peticiones por minuto
    private final Bucket authBucket = Bucket.builder()
            .addLimit(Bandwidth.classic(10,
                    Refill.intervally(10, Duration.ofMinutes(1))))
            .build();

    // Expedientes: 30 peticiones por minuto
    private final Bucket apiBucket = Bucket.builder()
            .addLimit(Bandwidth.classic(30,
                    Refill.intervally(30, Duration.ofMinutes(1))))
            .build();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        Bucket target = null;

        if (path.startsWith("/api/v1/auth/login")) {
            target = authBucket;
        } else if (path.startsWith("/api/v1/expedientes")) {
            target = apiBucket;
        }

        if (target == null || target.tryConsume(1)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Rate Limit superado: HTTP 429 con cuerpo RFC 7807
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Retry-After", "60");

        String json = """
                {
                  "type": "%s",
                  "title": "%s",
                  "status": 429,
                  "detail": "%s",
                  "instance": "%s"
                }
                """.formatted(
                "https://medivault.ucr.ac.cr/rate-limit",
                "Demasiadas Peticiones",
                "Limite superado. Espere 60s.",
                path.replace("\"", "")
        );

        response.getWriter().write(json);
    }
}
