-- ====================================================================
-- SISTEMA DE SEGURIDAD MEDIVAULT WEB
-- Datos Iniciales de Prueba (Semilla / Seed Data)
-- Contraseña unificada para todas las cuentas: Password123!
-- Hash BCrypt: $2a$10$AL7WTMCMPiB.OpqZ3UDNae1i6sw/c36bzTo/OdqJRlELT4xnpYS5a
-- ====================================================================

-- 1. Inserción de Usuarios con Roles RBAC
INSERT INTO USUARIOS (
    id, username, password_hash, nombre_completo, email, rol, estado
) VALUES 
(1, 'admin_root', 
 '$2a$10$AL7WTMCMPiB.OpqZ3UDNae1i6sw/c36bzTo/OdqJRlELT4xnpYS5a', 
 'Licda. Sofia Carvajal (Auditora)', 'admin@medivault.ucr.ac.cr', 
 'ROLE_ADMIN', 'ACTIVO'),

(2, 'doctor_smith', 
 '$2a$10$AL7WTMCMPiB.OpqZ3UDNae1i6sw/c36bzTo/OdqJRlELT4xnpYS5a', 
 'Dr. John Smith M.', 'jsmith@medivault.ucr.ac.cr', 
 'ROLE_DOCTOR', 'ACTIVO'),

(3, 'doctora_vargas', 
 '$2a$10$AL7WTMCMPiB.OpqZ3UDNae1i6sw/c36bzTo/OdqJRlELT4xnpYS5a', 
 'Dra. Elena Vargas P.', 'evargas@medivault.ucr.ac.cr', 
 'ROLE_DOCTOR', 'ACTIVO'),

(4, 'paciente_carlos', 
 '$2a$10$AL7WTMCMPiB.OpqZ3UDNae1i6sw/c36bzTo/OdqJRlELT4xnpYS5a', 
 'Carlos Mora Jimenez', 'cmora@gmail.com', 
 'ROLE_PACIENTE', 'ACTIVO'),

(5, 'paciente_maria', 
 '$2a$10$AL7WTMCMPiB.OpqZ3UDNae1i6sw/c36bzTo/OdqJRlELT4xnpYS5a', 
 'Maria Fernandez Soto', 'mfernandez@gmail.com', 
 'ROLE_PACIENTE', 'ACTIVO'),

(6, 'paciente_ana', 
 '$2a$10$AL7WTMCMPiB.OpqZ3UDNae1i6sw/c36bzTo/OdqJRlELT4xnpYS5a', 
 'Ana Belen Quiros', 'aquiros@gmail.com', 
 'ROLE_PACIENTE', 'ACTIVO');

-- 2. Inserción de Expedientes Médicos Confidenciales
INSERT INTO EXPEDIENTES_MEDICOS (
    id, paciente_id, medico_asignado_id, codigo_expediente, 
    diagnostico_principal, notas_clinicas, nivel_confidencialidad
) VALUES 
(101, 4, 2, 'EXP-2026-001', 
 'Hipertension Arterial Grado 2', 
 'Paciente refiere cefaleas frecuentes. Presion arterial 145/95 mmHg. ' ||
 'Tratamiento iniciado con Enalapril 20mg cada 12 horas. ' ||
 'Control en 30 dias con perfil lipidico completo.', 
 'ALTO'),

(102, 5, 3, 'EXP-2026-002', 
 'Diabetes Mellitus Tipo 2 Descompensada', 
 'Glucemia en ayunas elevada (165 mg/dL). HbA1c en 8.2%. ' ||
 'Se prescribe Metformina 850mg con comidas principales y dieta estricta. ' ||
 'Remision prioritaria al servicio de nutricion.', 
 'ALTO'),

(103, 6, 2, 'EXP-2026-003', 
 'Asma Bronquial Moderada Persistente', 
 'Episodio de broncoespasmo posterior a exposicion a polen ambiental. ' ||
 'Saturacion SpO2 inicial 93%. Se administra nebulizacion con Salbutamol. ' ||
 'Mantenimiento con Budesonida inhalada dos disparos al dia.', 
 'MEDIO');

-- 3. Inserción de Registro Inicial de Auditoría
INSERT INTO AUDIT_LOGS (
    username, ip_origen, accion, recurso_solicitado, codigo_estado, detalle_evento
) VALUES 
('SISTEMA', '127.0.0.1', 'INICIALIZACION_DATOS', '/database/seed', 
 200, 'Carga exitosa de esquemas y registros de seguridad iniciales');

