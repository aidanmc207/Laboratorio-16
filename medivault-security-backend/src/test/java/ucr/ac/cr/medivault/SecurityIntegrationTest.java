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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Reproduce las pruebas de seguridad del Paso 10 (cURL) con MockMvc.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SecurityIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper mapper;

    private String login(String username) throws Exception {
        MvcResult r = mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"Password123!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();
        JsonNode body = mapper.readTree(r.getResponse().getContentAsString());
        return body.get("token").asText();
    }

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
    void prueba4_ataqueIdorBloqueadoConRfc7807() throws Exception {
        String tokenMaria = login("paciente_maria");

        mvc.perform(get("/api/v1/expedientes/101")
                        .header("Authorization", "Bearer " + tokenMaria))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type").value("https://medivault.ucr.ac.cr/forbidden"))
                .andExpect(jsonPath("$.title").value("Acceso Prohibido (IDOR / BOLA)"))
                .andExpect(jsonPath("$.status").value(403));
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

    @Test
    @Order(7)
    void prueba5_fuerzaBrutaBloqueadaConRateLimiting() throws Exception {
        boolean bloqueado = false;
        for (int i = 0; i < 12; i++) {
            MvcResult r = mvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"username\":\"admin_root\",\"password\":\"ClaveIncorrecta1\"}"))
                    .andReturn();
            int code = r.getResponse().getStatus();
            if (code == 429) {
                assertThat(r.getResponse().getHeader("Retry-After")).isEqualTo("60");
                bloqueado = true;
                break;
            }
            assertThat(code).isEqualTo(401);
        }
        assertThat(bloqueado).isTrue();
    }
}
