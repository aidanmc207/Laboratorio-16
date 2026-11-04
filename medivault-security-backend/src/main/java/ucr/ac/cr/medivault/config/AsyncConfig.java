package ucr.ac.cr.medivault.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * Pool de hilos dedicado a la auditoria: las escrituras en AUDIT_LOGS se
 * ejecutan fuera del hilo de la peticion para no degradar los tiempos de
 * respuesta de la API.
 */
@Configuration
@EnableAsync
public class AsyncConfig {

    public static final String AUDIT_EXECUTOR = "auditExecutor";

    @Bean(name = AUDIT_EXECUTOR)
    public Executor auditExecutor() {
        ThreadPoolTaskExecutor ex = new ThreadPoolTaskExecutor();
        ex.setCorePoolSize(2);
        ex.setMaxPoolSize(4);
        ex.setQueueCapacity(1000);
        ex.setThreadNamePrefix("audit-");
        // Si la cola se llena, la peticion registra el evento ella misma:
        // nunca se pierden eventos de seguridad.
        ex.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        ex.initialize();
        return ex;
    }
}
