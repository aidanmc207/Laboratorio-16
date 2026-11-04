package ucr.ac.cr.medivault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import ucr.ac.cr.medivault.business.SecurityAuditorService;
import ucr.ac.cr.medivault.data.AuditLogRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Reproduce las pruebas de seguridad del Paso 10 (cURL), la Parte 2 y
 * el checklist del Reto Autonomo (Parte 3) con MockMvc.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SecurityIntegrationTest {

    // Cada login de los tests usa una IP distinta para no agotar el bucket por IP
    private static final AtomicInteger IP_SEQ = new AtomicInteger(1);

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private AuditLogRepository auditRepo;

    private static MockHttpServletRequestBuilder desdeIp(MockHttpServletRequestBuilder b, String ip) {
        return b.with(req -> {
            req.setRemoteAddr(ip);
            return req;
        });
    }

    private static MockHttpServletRequestBuilder loginRequest(String username, String password) {
        return post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}");
    }

    private String login(String username) throws Exception {
        String ip = "10.0.0." + IP_SEQ.getAndIncrement();
        MvcResult r = mvc.perform(desdeIp(loginRequest(username, "Password123!"), ip))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();
        JsonNode body = mapper.readTree(r.getResponse().getContentAsString());
        return body.get("token").asText();
    }

    /** La auditoria es asincrona: espera (maximo 5 s) a que aparezca el registro. */
    private static long esperar(LongSupplier conteo, long esperado) throws InterruptedException {
        long valor = conteo.getAsLong();
        for (int i = 0; i < 50 && valor < esperado; i++) {
            Thread.sleep(100);
            valor = conteo.getAsLong();
        }
        return valor;
    }

    // ------------------------------------------------------------------
    // Parte 1 - Paso 10
    // ------------------------------------------------------------------

    @Test
    @Order(1)
    void prueba1y3_loginYConsultaDeExpedientePropio() throws Exception {
        String tokenCarlos = login("paciente_carlos");

        mvc.perform(get("/api/v1/expedientes/101")
                        .header("Authorization", "Bearer " + tokenCarlos))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.codigoExpediente").value("EXP-2026-001"))
                .andExpect(jsonPath("$.pacienteNombre").value("Carlos Mora Jimenez"));
    }

    @Test
    @Order(2)
    void prueba2_cabecerasDefensivas() throws Exception {
        mvc.perform(get("/api/v1/expedientes/101").secure(true))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().exists("Content-Security-Policy"))
                .andExpect(header().string("Strict-Transport-Security",
                        "max-age=31536000 ; includeSubDomains"))
                .andExpect(header().string("Cache-Control",
                        "no-cache, no-store, max-age=0, must-revalidate"));
    }

    @Test
    @Order(3)
    void prueba4_ataqueIdorBloqueadoConRfc7807YAuditado() throws Exception {
        String tokenMaria = login("paciente_maria");

        mvc.perform(desdeIp(get("/api/v1/expedientes/101"), "198.51.100.23")
                        .header("Authorization", "Bearer " + tokenMaria))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type").value("https://medivault.ucr.ac.cr/forbidden"))
                .andExpect(jsonPath("$.title").value("Acceso Prohibido (IDOR / BOLA)"))
                .andExpect(jsonPath("$.status").value(403));

        // Parte 3 - Req. B: el intento queda registrado en AUDIT_LOGS
        long registros = esperar(() -> auditRepo.countByAccionAndIpOrigen(
                SecurityAuditorService.IDOR_ATTEMPT_BLOCKED, "198.51.100.23"), 1);
        assertThat(registros).isEqualTo(1);
    }

    @Test
    @Order(4)
    void doctorNoAsignadoBloqueadoPorBola() throws Exception {
        String tokenVargas = login("doctora_vargas");

        mvc.perform(get("/api/v1/expedientes/101")
                        .header("Authorization", "Bearer " + tokenVargas))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(5)
    void validacionDtoSinFugaDeInformacion() throws Exception {
        String tokenSmith = login("doctor_smith");

        mvc.perform(post("/api/v1/expedientes")
                        .header("Authorization", "Bearer " + tokenSmith)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"pacienteId\":-1,\"codigoExpediente\":\"XYZ\","
                                + "\"diagnosticoPrincipal\":\"a\",\"notasClinicas\":\"corta\","
                                + "\"nivelConfidencialidad\":\"TOTAL\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Error de Validacion"))
                .andExpect(jsonPath("$.invalid_fields.codigoExpediente").exists())
                .andExpect(jsonPath("$.trace").doesNotExist());

        // ID con formato invalido -> 400 controlado, no 500
        mvc.perform(get("/api/v1/expedientes/abc")
                        .header("Authorization", "Bearer " + tokenSmith))
                .andExpect(status().isBadRequest());

        // ID inexistente -> 404 RFC 7807
        mvc.perform(get("/api/v1/expedientes/9999")
                        .header("Authorization", "Bearer " + tokenSmith))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.title").value("Recurso No Encontrado"));
    }

    // ------------------------------------------------------------------
    // Parte 2
    // ------------------------------------------------------------------

    @Test
    @Order(6)
    void parte2_actualizacionDeNotasSegura() throws Exception {
        String tokenSmith = login("doctor_smith");
        String tokenVargas = login("doctora_vargas");
        String tokenCarlos = login("paciente_carlos");
        String body = "{\"notasClinicas\":\"Control de presion estable, continuar tratamiento.\"}";

        // Medico asignado: permitido
        mvc.perform(patch("/api/v1/expedientes/101/notas")
                        .header("Authorization", "Bearer " + tokenSmith)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isNoContent());

        // Medico no asignado: bloqueado
        mvc.perform(patch("/api/v1/expedientes/101/notas")
                        .header("Authorization", "Bearer " + tokenVargas)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());

        // Paciente: bloqueado
        mvc.perform(patch("/api/v1/expedientes/101/notas")
                        .header("Authorization", "Bearer " + tokenCarlos)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());

        // Sin token: 401
        mvc.perform(patch("/api/v1/expedientes/101/notas")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized());
    }

    // ------------------------------------------------------------------
    // Parte 3 - Reto Autonomo
    // ------------------------------------------------------------------

    @Test
    @Order(7)
    void parte3A_sextoIntentoDesdeLaMismaIpRecibe429() throws Exception {
        String ip = "203.0.113.7";
        List<Integer> codigos = new ArrayList<>();

        for (int i = 0; i < 6; i++) {
            MvcResult r = mvc.perform(desdeIp(loginRequest("admin_root", "ClaveIncorrecta1"), ip))
                    .andReturn();
            codigos.add(r.getResponse().getStatus());
            if (i == 5) {
                assertThat(r.getResponse().getHeader("Retry-After")).isEqualTo("60");
            }
        }

        assertThat(codigos).containsExactly(401, 401, 401, 401, 401, 429);

        // Parte 3 - Req. B: los 5 fallos de login quedaron auditados con su IP
        long registros = esperar(() -> auditRepo.countByAccionAndIpOrigen(
                SecurityAuditorService.LOGIN_FAILED, ip), 5);
        assertThat(registros).isEqualTo(5);
    }

    @Test
    @Order(8)
    void parte3A_otraIpTieneSuPropioBucket() throws Exception {
        // La IP anterior esta bloqueada, pero otra IP sigue pudiendo autenticarse
        mvc.perform(desdeIp(loginRequest("admin_root", "Password123!"), "203.0.113.8"))
                .andExpect(status().isOk());

        mvc.perform(desdeIp(loginRequest("admin_root", "Password123!"), "203.0.113.7"))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    @Order(9)
    void parte3A_seRespetaXForwardedFor() throws Exception {
        String proxy = "172.16.0.1";
        // Seis peticiones a traves del mismo proxy pero de clientes distintos: ninguna se bloquea
        for (int i = 1; i <= 6; i++) {
            mvc.perform(desdeIp(loginRequest("admin_root", "ClaveIncorrecta1"), proxy)
                            .header("X-Forwarded-For", "192.0.2." + i + ", " + proxy))
                    .andExpect(status().isUnauthorized());
        }

        // Fallos de login atribuidos a la IP real del cliente, no a la del proxy
        long registros = esperar(() -> auditRepo.countByAccionAndIpOrigen(
                SecurityAuditorService.LOGIN_FAILED, "192.0.2.3"), 1);
        assertThat(registros).isEqualTo(1);
    }

    @Test
    @Order(10)
    void parte3B_consultaDeAuditoriaSoloAdminYSinDatosClinicos() throws Exception {
        String tokenAdmin = login("admin_root");
        String tokenCarlos = login("paciente_carlos");

        mvc.perform(get("/api/v1/auditoria")
                        .param("accion", SecurityAuditorService.IDOR_ATTEMPT_BLOCKED)
                        .header("Authorization", "Bearer " + tokenAdmin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].accion").value("IDOR_ATTEMPT_BLOCKED"))
                .andExpect(jsonPath("$[0].codigoEstado").value(403))
                .andExpect(jsonPath("$[0].fechaEvento").exists())
                .andExpect(jsonPath("$[0].notasClinicas").doesNotExist())
                .andExpect(jsonPath("$[0].diagnosticoPrincipal").doesNotExist());

        mvc.perform(get("/api/v1/auditoria")
                        .header("Authorization", "Bearer " + tokenCarlos))
                .andExpect(status().isForbidden());
    }
}
