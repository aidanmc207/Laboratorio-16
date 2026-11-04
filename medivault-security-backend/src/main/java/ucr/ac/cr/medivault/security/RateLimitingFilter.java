package ucr.ac.cr.medivault.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Filtro de Rate Limiting granular por direccion IP (Token Bucket con Bucket4j).
 *
 * Cada IP de cliente obtiene su propio bucket:
 *  - Login:       5 intentos por minuto por IP (el 6.o recibe HTTP 429).
 *  - Expedientes: 30 peticiones por minuto por IP.
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    static final int LOGIN_LIMIT_PER_MINUTE = 5;
    static final int API_LIMIT_PER_MINUTE = 30;

    private static final String LOGIN_PATH = "/api/v1/auth/login";
    private static final String API_PATH = "/api/v1/expedientes";

    // Un bucket independiente por IP para cada grupo de endpoints
    private final Map<String, Bucket> loginBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> apiBuckets = new ConcurrentHashMap<>();

    private final ClientIpResolver ipResolver;

    public RateLimitingFilter(ClientIpResolver ipResolver) {
        this.ipResolver = ipResolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        Bucket target = null;

        if (path.startsWith(LOGIN_PATH)) {
            String ip = ipResolver.resolve(request);
            target = loginBuckets.computeIfAbsent(ip,
                    k -> newBucket(LOGIN_LIMIT_PER_MINUTE));
        } else if (path.startsWith(API_PATH)) {
            String ip = ipResolver.resolve(request);
            target = apiBuckets.computeIfAbsent(ip,
                    k -> newBucket(API_LIMIT_PER_MINUTE));
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

    private static Bucket newBucket(int capacityPerMinute) {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(capacityPerMinute)
                        .refillIntervally(capacityPerMinute, Duration.ofMinutes(1))
                        .build())
                .build();
    }
}
