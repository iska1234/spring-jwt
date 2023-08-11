package pe.aaron.bregante.jwt.controller;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import pe.aaron.bregante.jwt.model.ERole;
import pe.aaron.bregante.jwt.model.RoleEntity;
import pe.aaron.bregante.jwt.model.UserEntity;
import pe.aaron.bregante.jwt.repository.UserRepository;


@RestController
public class AaronJwtController {

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private PasswordEncoder passwordEncoder;

	@PostMapping("/crearUsuario")
	public ResponseEntity<?> crearUsuario(@Valid @RequestBody CreateUserDTO createUserDTO) {

		Set<RoleEntity> roles = createUserDTO.getRoles().stream()
				.map(rolo -> RoleEntity.builder().name(ERole.valueOf(rolo)).build()).collect(Collectors.toSet());

		UserEntity userEntity = UserEntity.builder().username(createUserDTO.getUsername())
				.password(passwordEncoder.encode(
						createUserDTO.getPassword()))
				.email(createUserDTO.getEmail()).roles(roles).build();

		userRepository.save(userEntity);
		return ResponseEntity.ok(userEntity);
	}
	
	@DeleteMapping("/deleteUser")
	public String deleteUser(@RequestParam String id) {
		userRepository.deleteById(Long.parseLong(id));
		return "Se elimino el usuario con id: " + id;
	}
	
	@GetMapping("/test")
	public String test() {
		return "Hola! Has accedido al metodo publico";
	}

	
	@GetMapping("/accessAdmin")
    @PreAuthorize("hasRole('ADMIN')")
    public String accessAdmin(){
        return "Hola, has accedido con rol de ADMIN";
    }

    @GetMapping("/accessUser")
    @PreAuthorize("hasRole('USER')")
    public String accessUser(){
        return "Hola, has accedido con rol de USER";
    }

    @GetMapping("/accessInvited")
    @PreAuthorize("hasRole('INVITED')")
    public String accessInvited(){
        return "Hola, has accedido con rol de INVITED";
    }
}
