# Laboratorio 16 – MediVault Web

**IF0009 – Desarrollo de Software IV · UCR Sede del Atlántico, Recinto Paraíso · II-2026**

Hardening defensivo y mitigación de vulnerabilidades OWASP en una API REST con **Spring Boot 3.3**, **Spring Security 6**, JWT (JJWT 0.12), Jakarta Bean Validation, `ProblemDetail` (RFC 7807) y Rate Limiting con **Bucket4j**.

## Estado del proyecto

| Sección del enunciado | Estado |
|---|---|
| Parte 1 – Pasos 1 a 9 (pom, configuración, entidades, JWT, SecurityConfig, Rate Limiting, DTOs, RFC 7807, servicios, controladores) | ✅ Completo |
| Parte 1 – Paso 10 (pruebas de seguridad) | ✅ Automatizadas en `SecurityIntegrationTest` |
| Parte 2 – Depuración del endpoint `PATCH /{id}/notas` | ✅ Versión segura implementada |
| Parte 3 – Requerimiento A: Rate Limiting por IP | ⏳ Pendiente |
| Parte 3 – Requerimiento B: Auditoría en `AUDIT_LOGS` (`SecurityAuditorService`) | ⏳ Pendiente |

## Estructura

```
medivault-security-backend/
├── pom.xml
└── src/
    ├── main/java/ucr/ac/cr/medivault/
    │   ├── domain/        Usuario, Rol, ExpedienteMedico
    │   ├── data/          UsuarioRepository, ExpedienteMedicoRepository
    │   ├── business/      AuthService, ExpedienteService
    │   ├── controller/    AuthController, ExpedienteController, dto/
    │   ├── security/      SecurityConfig, JwtTokenProvider, JwtAuthenticationFilter, RateLimitingFilter
    │   ├── exception/     AccessDeniedSecurityException, ResourceNotFoundException, GlobalSecurityExceptionHandler
    │   └── MedivaultApplication.java
    ├── main/resources/    application.yml, schema.sql, data.sql
    └── test/java/...      SecurityIntegrationTest
```

## Requisitos y ejecución

- Java 21 LTS o superior (el enunciado admite JDK 25 o 21 LTS)
- Maven 3.9+

```bash
cd medivault-security-backend
mvn test              # ejecuta las pruebas de seguridad
mvn spring-boot:run   # levanta la API en http://localhost:8080
```

Usuarios de prueba (contraseña `Password123!`): `admin_root`, `doctor_smith`, `doctora_vargas`, `paciente_carlos`, `paciente_maria`, `paciente_ana`.

## Endpoints

| Método | Ruta | Acceso |
|---|---|---|
| POST | `/api/v1/auth/login` | Público (10 req/min) |
| GET | `/api/v1/expedientes/{id}` | Autenticado + verificación de propiedad |
| GET | `/api/v1/expedientes/mis-expedientes` | Autenticado |
| POST | `/api/v1/expedientes` | `ROLE_DOCTOR` / `ROLE_ADMIN` |
| PATCH | `/api/v1/expedientes/{id}/notas` | Solo el médico asignado (Parte 2) |

## Pruebas con cURL (Paso 10)

```bash
# Prueba 1: login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"paciente_carlos","password":"Password123!"}'

# Prueba 2: cabeceras defensivas
curl -I http://localhost:8080/api/v1/expedientes/101 -H "Authorization: Bearer <TOKEN_CARLOS>"

# Prueba 3: expediente propio -> 200
curl http://localhost:8080/api/v1/expedientes/101 -H "Authorization: Bearer <TOKEN_CARLOS>"

# Prueba 4: IDOR -> 403 RFC 7807
curl http://localhost:8080/api/v1/expedientes/101 -H "Authorization: Bearer <TOKEN_MARIA>"

# Prueba 5: fuerza bruta -> 429 + Retry-After: 60
for i in {1..12}; do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8080/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin_root","password":"ClaveIncorrecta1"}'
done
```

Respuesta verificada de la Prueba 4:

```json
{
  "type": "https://medivault.ucr.ac.cr/forbidden",
  "title": "Acceso Prohibido (IDOR / BOLA)",
  "status": 403,
  "detail": "Violacion IDOR: Acceso no autorizado.",
  "instance": "/api/v1/expedientes/101"
}
```

## Ajustes respecto al código del enunciado

1. **`X-Content-Type-Options` y `Cache-Control`**: el código del enunciado usa `ContentTypeOptionsConfig::disable` y `CacheControlConfig::disable`, lo cual *elimina* esas cabeceras. Se cambiaron a `Customizer.withDefaults()` para emitir `nosniff` y `no-cache, no-store`, tal como exige la rúbrica.
2. **Registro doble de filtros**: `JwtAuthenticationFilter` y `RateLimitingFilter` son `@Component`, por lo que Spring Boot también los registra en el contenedor de Servlets. Se desactivó ese registro con `FilterRegistrationBean#setEnabled(false)` para que solo se ejecuten dentro de la cadena de Spring Security.
3. **401/403 en RFC 7807**: se configuró `authenticationEntryPoint` y `accessDeniedHandler` para que las peticiones sin token o sin permisos también devuelvan `ProblemDetail`.
4. **Manejador global ampliado**: además de los casos del enunciado, captura JSON mal formado, IDs no numéricos, rutas inexistentes, conflictos de integridad y métodos no soportados, con códigos 400/404/405/409/415 en lugar de un 500 genérico.
5. **Prueba 5**: con `"password": "err"` la petición falla primero la validación del DTO (mínimo 8 caracteres) y devuelve **400**, no 401. Para obtener 401 se usa una contraseña de 8+ caracteres incorrecta.
6. **Prueba 2**: `curl -I` envía un `HEAD`, que el endpoint de login no admite; se recomienda inspeccionar las cabeceras sobre `/api/v1/expedientes/101`. `Strict-Transport-Security` solo se envía sobre HTTPS (comportamiento estándar de Spring Security).
7. Nombres de clases: se usaron `AccessDeniedSecurityException` y `GlobalSecurityExceptionHandler`, tal como aparecen en el Paso 7.

## Parte 2 – Análisis del endpoint vulnerable

**Fallas identificadas** en `actualizarNotasVulnerable`:
- No recibe `Authentication`: cualquier usuario autenticado podía modificar cualquier expediente (BOLA).
- No verifica rol ni que el solicitante sea el `medicoAsignado`.
- Acepta un `String` crudo sin validación de longitud ni contenido.
- `findById(id).orElseThrow()` lanza `NoSuchElementException`, que terminaba como un 500.

**Solución aplicada**: `PATCH /api/v1/expedientes/{id}/notas` con `@PreAuthorize("hasAuthority('ROLE_DOCTOR')")`, un DTO validado (`ActualizarNotasRequestDto`, de 10 a 4000 caracteres) y `ExpedienteService#actualizarNotasDefensivo`, que verifica que el solicitante sea el médico asignado y lanza `AccessDeniedSecurityException` o `ResourceNotFoundException` según corresponda.

## Pendiente (Parte 3 – Reto Autónomo)

- **Requerimiento A**: en `RateLimitingFilter`, obtener la IP del cliente (`X-Forwarded-For` → `getRemoteAddr()`), mantener un `ConcurrentHashMap<String, Bucket>` por IP y limitar el login a 5 intentos por minuto por IP (el 6.º debe recibir 429).
- **Requerimiento B**: crear la entidad/repositorio de `AUDIT_LOGS` (la tabla ya existe en `schema.sql`) y un `SecurityAuditorService` que registre `IDOR_ATTEMPT_BLOCKED` (403) y `LOGIN_FAILED` (401) con usuario, IP, recurso y fecha.
