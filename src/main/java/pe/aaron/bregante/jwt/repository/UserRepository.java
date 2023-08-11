package pe.aaron.bregante.jwt.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import pe.aaron.bregante.jwt.model.UserEntity;



@Repository
public interface UserRepository extends CrudRepository<UserEntity, Long> {
	
	Optional<UserEntity> findByUsername(String username);

}
