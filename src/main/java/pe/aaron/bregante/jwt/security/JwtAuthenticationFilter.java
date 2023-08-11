package pe.aaron.bregante.jwt.security;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import pe.aaron.bregante.jwt.model.UserEntity;


public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
	private JwtUtil jwtUtil;
	
	public JwtAuthenticationFilter(JwtUtil jwtUtils) {
		this.jwtUtil = jwtUtils;
	}
	
	@Override
	public Authentication attemptAuthentication( HttpServletRequest request
												,HttpServletResponse response
												) throws AuthenticationException {				
		UserEntity userEntity = null;
		String username = "";
		String password = "";
		
		try {
			userEntity = new ObjectMapper().readValue(request.getInputStream(), UserEntity.class);
			username = userEntity.getUsername();
			password = userEntity.getPassword();			
		} catch (StreamReadException e) {
			throw new RuntimeException(e);
		} catch (DatabindException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username,password);
		return getAuthenticationManager().authenticate(authenticationToken);
	}
	
	@Override
	protected void successfulAuthentication (HttpServletRequest request
			,HttpServletResponse response
			,FilterChain chain
			,Authentication authResult) throws IOException,ServletException {		
	
		User user = (User) authResult.getPrincipal();
		String token = jwtUtil.generateAccesToken(user.getUsername());
	
		response.addHeader("Autorization", token);
		Map<String, Object> httpResponse = new HashMap<>();
		httpResponse.put("token", token);
		httpResponse.put("Message", "Autenticacion correcta");
		httpResponse.put("Username", user.getUsername());
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(httpResponse));
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(org.springframework.http.MediaType.APPLICATION_JSON_VALUE);
		response.getWriter().flush();
		super.successfulAuthentication(request, response, chain, authResult);

	}

}
