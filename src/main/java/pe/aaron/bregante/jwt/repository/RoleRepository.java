package pe.aaron.bregante.jwt.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import pe.aaron.bregante.jwt.model.RoleEntity;



@Repository
public interface RoleRepository extends CrudRepository<RoleEntity, Long> {

}
