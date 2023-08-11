package pe.aaron.bregante.jwt.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
//import io.jsonwebtoken.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import pe.aaron.bregante.jwt.service.UserDetailsServiceImpl;


@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter  {
	
	@Autowired
	private JwtUtil jwtUtil;
	
	@Autowired
	private UserDetailsServiceImpl userDetailsServiceImpl;
	

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
		
		String tokenHeader = request.getHeader("Authorization");
		
		 if(tokenHeader != null && tokenHeader.startsWith("Bearer ")){
	            String token = tokenHeader.substring(7);

	            if(jwtUtil.isTokenValid(token)){
	                String username = jwtUtil.getUsernameFromToken(token);
	                UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(username);

	                UsernamePasswordAuthenticationToken authenticationToken =
	                        new UsernamePasswordAuthenticationToken(username, null, userDetails.getAuthorities());

	                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
	            }
	        }
		 filterChain.doFilter(request,response);		
	}
	


}
