package ucr.ac.cr.medivault.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;
    private final RateLimitingFilter rateFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtFilter,
                          RateLimitingFilter rateFilter) {
        this.jwtFilter = jwtFilter;
        this.rateFilter = rateFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // 1. Desactivacion CSRF (API stateless con Bearer JWT)
            .csrf(AbstractHttpConfigurer::disable)

            // 2. Sesion sin estado (Stateless)
            .sessionManagement(s -> s
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // 3. Reglas de Autorizacion
            .authorizeHttpRequests(a -> a
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/login").permitAll()
                .requestMatchers("/error").permitAll()
                .requestMatchers("/h2-console/**").denyAll()
                .requestMatchers("/api/v1/expedientes/**").authenticated()
                .anyRequest().authenticated())

            // 4. Respuestas 401/403 en formato RFC 7807 (sin fugas de informacion)
            .exceptionHandling(e -> e
                .authenticationEntryPoint((req, res, ex) ->
                    writeProblem(res, HttpServletResponse.SC_UNAUTHORIZED,
                        "No Autenticado",
                        "Se requiere un token Bearer valido.",
                        "https://medivault.ucr.ac.cr/unauthorized",
                        req.getRequestURI()))
                .accessDeniedHandler((req, res, ex) ->
                    writeProblem(res, HttpServletResponse.SC_FORBIDDEN,
                        "Acceso Prohibido",
                        "No posee permisos para este recurso.",
                        "https://medivault.ucr.ac.cr/forbidden",
                        req.getRequestURI())))

            // 5. Hardening de Cabeceras HTTP
            .headers(h -> h
                // Bloquea Clickjacking (no iframes)
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                // X-Content-Type-Options: nosniff (bloquea MIME-Sniffing)
                .contentTypeOptions(Customizer.withDefaults())
                // CSP Nivel 3
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives(
                        "default-src 'self'; " +
                        "frame-ancestors 'none'; " +
                        "object-src 'none'; " +
                        "base-uri 'self'; " +
                        "form-action 'self'"))
                // HSTS: obliga uso de HTTPS (1 anio)
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000))
                // Cache-Control: no-cache, no-store (prohibe cache de datos medicos)
                .cacheControl(Customizer.withDefaults())
                // No filtrar el Referer hacia terceros
                .referrerPolicy(r -> r.policy(
                    org.springframework.security.web.header.writers
                        .ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)))

            // 6. Insercion de Filtros en el Pipeline
            .addFilterBefore(rateFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /*
     * Los filtros anotados con @Component son registrados automaticamente por
     * Spring Boot en el contenedor de Servlets. Se desactiva ese registro para
     * que solo se ejecuten dentro de la cadena de Spring Security (de lo
     * contrario el contexto de seguridad del JWT se perderia).
     */
    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilterRegistration(
            JwtAuthenticationFilter filter) {
        FilterRegistrationBean<JwtAuthenticationFilter> reg = new FilterRegistrationBean<>(filter);
        reg.setEnabled(false);
        return reg;
    }

    @Bean
    public FilterRegistrationBean<RateLimitingFilter> rateFilterRegistration(
            RateLimitingFilter filter) {
        FilterRegistrationBean<RateLimitingFilter> reg = new FilterRegistrationBean<>(filter);
        reg.setEnabled(false);
        return reg;
    }

    private static void writeProblem(HttpServletResponse res, int status, String title,
                                     String detail, String type, String instance)
            throws IOException {
        res.setStatus(status);
        res.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        res.setCharacterEncoding("UTF-8");
        res.getWriter().write("""
                {
                  "type": "%s",
                  "title": "%s",
                  "status": %d,
                  "detail": "%s",
                  "instance": "%s"
                }
                """.formatted(type, title, status, detail, instance.replace("\"", "")));
    }
}
