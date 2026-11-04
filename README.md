# Laboratorio 16 – MediVault Web

**IF0009 – Desarrollo de Software IV · UCR Sede del Atlántico, Recinto Paraíso · II-2026**

Hardening defensivo y mitigación de vulnerabilidades OWASP en una API REST con **Spring Boot 3.3**, **Spring Security 6**, JWT (JJWT 0.12), Jakarta Bean Validation, `ProblemDetail` (RFC 7807) y Rate Limiting con **Bucket4j**.

## Estado del proyecto

| Sección del enunciado | Estado |
|---|---|
| Parte 1 – Pasos 1 a 9 (pom, configuración, entidades, JWT, SecurityConfig, Rate Limiting, DTOs, RFC 7807, servicios, controladores) | ✅ Completo |
| Parte 1 – Paso 10 (pruebas de seguridad) | ✅ Automatizadas en `SecurityIntegrationTest` |
| Parte 2 – Depuración del endpoint `PATCH /{id}/notas` | ✅ Versión segura implementada |
| Parte 3 – Requerimiento A: Rate Limiting por IP | ✅ Completo |
| Parte 3 – Requerimiento B: Auditoría en `AUDIT_LOGS` (`SecurityAuditorService`) | ✅ Completo |

## Estructura

```
medivault-security-backend/
├── pom.xml
└── src/
    ├── main/java/ucr/ac/cr/medivault/
    │   ├── config/        AsyncConfig (pool de hilos de auditoría)
    │   ├── domain/        Usuario, Rol, ExpedienteMedico, AuditLog
    │   ├── data/          UsuarioRepository, ExpedienteMedicoRepository, AuditLogRepository
    │   ├── business/      AuthService, ExpedienteService, SecurityAuditorService
    │   ├── controller/    AuthController, ExpedienteController, AuditoriaController, dto/
    │   ├── security/      SecurityConfig, JwtTokenProvider, JwtAuthenticationFilter,
    │   │                  RateLimitingFilter, ClientIpResolver
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
| POST | `/api/v1/auth/login` | Público (5 intentos/min por IP) |
| GET | `/api/v1/expedientes/{id}` | Autenticado + verificación de propiedad |
| GET | `/api/v1/expedientes/mis-expedientes` | Autenticado |
| POST | `/api/v1/expedientes` | `ROLE_DOCTOR` / `ROLE_ADMIN` |
| PATCH | `/api/v1/expedientes/{id}/notas` | Solo el médico asignado (Parte 2) |
| GET | `/api/v1/auditoria?accion=&page=&size=` | `ROLE_ADMIN` (Parte 3) |

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

# Prueba 5 / Reto A: fuerza bruta -> 5 x 401 y el 6.º intento 429 + Retry-After: 60
for i in {1..6}; do
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

## Parte 3 – Reto Autónomo

### Requerimiento A: Rate Limiting granular por IP

- `ClientIpResolver` toma la **primera IP** de `X-Forwarded-For` (el cliente original cuando hay proxy inverso). Si la cabecera no existe o su valor no tiene formato de IP, usa `request.getRemoteAddr()`.
- `RateLimitingFilter` mantiene un `ConcurrentHashMap<String, Bucket>` por IP (`computeIfAbsent`, seguro ante concurrencia):
  - login: **5 intentos por minuto por IP**; el 6.º recibe **HTTP 429** con `Retry-After: 60` y cuerpo RFC 7807;
  - expedientes: 30 peticiones por minuto por IP.
- Bloquear una IP no afecta a las demás: cada cliente tiene su propio bucket.

> **Nota de seguridad:** `X-Forwarded-For` lo puede falsificar el cliente. Solo se debe confiar en esa cabecera si la API está detrás de un proxy que la reescribe. Para ignorarla, configure `medivault.security.trust-forwarded-header: false`.

### Requerimiento B: Auditoría de seguridad inmutable

- **Entidad `AuditLog`**: está marcada con `@Immutable`, no tiene setters y su constructor trunca cada campo al tamaño de la columna.
- **`AuditLogRepository`**: extiende `Repository` (no `JpaRepository`), así que solo expone inserción y consulta. No hay métodos de borrado ni de actualización.
- **`SecurityAuditorService`** registra dos eventos:
  - `IDOR_ATTEMPT_BLOCKED` (403): se dispara desde `GlobalSecurityExceptionHandler` cada vez que se lanza una `AccessDeniedSecurityException`. Guarda el usuario, la IP, el método y la ruta (que incluye el ID del expediente que se intentó vulnerar) y el motivo.
  - `LOGIN_FAILED` (401): se dispara desde `AuthController` ante cada credencial inválida. Guarda el usuario que se intentó usar y la IP.
- **Escritura desacoplada**: el registro es `@Async`, corre en un pool dedicado (`auditExecutor`) y usa una transacción `REQUIRES_NEW`. Así no se agrega latencia a la petición y el evento se guarda aunque la operación de negocio haga rollback. Si la escritura de auditoría falla, el error se registra en el log y la petición original no se ve afectada.
- **Sin datos clínicos**: la bitácora nunca guarda diagnósticos ni notas, solo metadatos de seguridad. La fecha (`fecha_evento`) la asigna la base de datos.
- **Consulta**: `GET /api/v1/auditoria`, restringida a `ROLE_ADMIN`. Se puede filtrar por `accion` y está paginada (máximo 100 registros por página).

### Checklist del reto

- [x] `RateLimitingFilter` mantiene buckets independientes por dirección IP del cliente.
- [x] 6 solicitudes consecutivas a `/api/v1/auth/login` desde la misma IP: la sexta recibe HTTP 429.
- [x] `AUDIT_LOGS` registra de forma automática e inmutable los incidentes IDOR y los fallos de login, con IP y timestamp.
- [x] La auditoría es asíncrona y desacoplada, y no expone datos clínicos.

Cada punto del checklist está cubierto por una prueba en `SecurityIntegrationTest` (10 pruebas en total).
