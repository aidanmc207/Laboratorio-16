-- ====================================================================
-- SISTEMA DE SEGURIDAD MEDIVAULT WEB
-- Esquema de Base de Datos H2 (ANSI SQL Standard)
-- ====================================================================

DROP TABLE IF EXISTS AUDIT_LOGS;
DROP TABLE IF EXISTS EXPEDIENTES_MEDICOS;
DROP TABLE IF EXISTS USUARIOS;

-- Tabla de Usuarios con roles RBAC y contraseñas hasheadas con BCrypt
CREATE TABLE USUARIOS (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(100) NOT NULL,
    nombre_completo VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    rol VARCHAR(20) NOT NULL,
    estado VARCHAR(20) NOT NULL DEFAULT 'ACTIVO',
    intentos_fallidos INT DEFAULT 0,
    cuenta_bloqueada BOOLEAN DEFAULT FALSE,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de Expedientes Médicos Confidenciales protegidos contra IDOR
CREATE TABLE EXPEDIENTES_MEDICOS (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    paciente_id BIGINT NOT NULL,
    medico_asignado_id BIGINT NOT NULL,
    codigo_expediente VARCHAR(30) NOT NULL UNIQUE,
    diagnostico_principal VARCHAR(255) NOT NULL,
    notas_clinicas TEXT NOT NULL,
    nivel_confidencialidad VARCHAR(20) NOT NULL DEFAULT 'ALTO',
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_expediente_paciente 
        FOREIGN KEY (paciente_id) REFERENCES USUARIOS(id),
    CONSTRAINT fk_expediente_medico 
        FOREIGN KEY (medico_asignado_id) REFERENCES USUARIOS(id)
);

-- Tabla de Registro de Auditoría de Seguridad Inmutable
CREATE TABLE AUDIT_LOGS (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    ip_origen VARCHAR(45) NOT NULL,
    accion VARCHAR(50) NOT NULL,
    recurso_solicitado VARCHAR(255) NOT NULL,
    codigo_estado INT NOT NULL,
    detalle_evento VARCHAR(255),
    fecha_evento TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Índices para optimizar búsquedas y reglas de seguridad
CREATE INDEX idx_usuarios_username ON USUARIOS(username);
CREATE INDEX idx_expedientes_paciente ON EXPEDIENTES_MEDICOS(paciente_id);
CREATE INDEX idx_expedientes_medico ON EXPEDIENTES_MEDICOS(medico_asignado_id);
CREATE INDEX idx_audit_fecha ON AUDIT_LOGS(fecha_evento);

