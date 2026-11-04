package ucr.ac.cr.medivault.data;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ucr.ac.cr.medivault.domain.ExpedienteMedico;

import java.util.List;
import java.util.Optional;

@Repository
public interface ExpedienteMedicoRepository extends JpaRepository<ExpedienteMedico, Long> {

    List<ExpedienteMedico> findByPacienteId(Long pacienteId);

    // Consulta JPA parametrizada contra SQLi
    @Query("SELECT e FROM ExpedienteMedico e " +
           "JOIN FETCH e.paciente " +
           "JOIN FETCH e.medicoAsignado " +
           "WHERE e.id = :id")
    Optional<ExpedienteMedico> findByIdWithDetails(@Param("id") Long id);
}
