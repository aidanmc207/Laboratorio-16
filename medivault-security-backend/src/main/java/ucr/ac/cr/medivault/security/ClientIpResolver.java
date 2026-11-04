package ucr.ac.cr.medivault.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.regex.Pattern;

/**
 * Obtiene la IP real del cliente.
 *
 * Si la aplicacion esta detras de un proxy inverso se toma la primera IP de
 * la cabecera X-Forwarded-For (cliente original). Si la cabecera no existe o
 * su valor no tiene forma de IP, se usa request.getRemoteAddr().
 *
 * La cabecera X-Forwarded-For la controla el cliente, por lo que solo debe
 * confiarse en ella cuando un proxy de confianza la reescribe. Puede
 * desactivarse con medivault.security.trust-forwarded-header=false.
 */
@Component
public class ClientIpResolver {

    private static final String XFF = "X-Forwarded-For";
    // IPv4 / IPv6 (solo caracteres validos, maximo 45 = longitud de ip_origen)
    private static final Pattern IP_PATTERN = Pattern.compile("^[0-9a-fA-F:.]{2,45}$");

    private final boolean trustForwardedHeader;

    public ClientIpResolver(
            @Value("${medivault.security.trust-forwarded-header:true}") boolean trustForwardedHeader) {
        this.trustForwardedHeader = trustForwardedHeader;
    }

    public String resolve(HttpServletRequest request) {
        if (trustForwardedHeader) {
            String forwarded = request.getHeader(XFF);
            if (StringUtils.hasText(forwarded)) {
                String first = forwarded.split(",")[0].trim();
                if (IP_PATTERN.matcher(first).matches()) {
                    return first;
                }
            }
        }
        return request.getRemoteAddr();
    }
}
