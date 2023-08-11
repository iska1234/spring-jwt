package pe.aaron.bregante.jwt.security;

import org.springframework.context.annotation.Bean;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import pe.aaron.bregante.jwt.service.UserDetailsServiceImpl;

import org.springframework.beans.factory.annotation.Autowired;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    JwtUtil jwtUtils;

    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    JwtAuthorizationFilter authorizationFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, AuthenticationManager authenticationManager) throws Exception {

    	  JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(jwtUtils);
          jwtAuthenticationFilter.setAuthenticationManager(authenticationManager);
          jwtAuthenticationFilter.setFilterProcessesUrl("/login");
          return httpSecurity
                  .csrf(config -> config.disable())
                  .authorizeHttpRequests(auth -> {
                      auth.requestMatchers("/test").permitAll();                    
                      auth.requestMatchers("/crearUsuario").permitAll();
                      auth.anyRequest().authenticated();
                  })
                  .sessionManagement(session -> {
                      session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                  })
                  .addFilter(jwtAuthenticationFilter)
                  .addFilterBefore(authorizationFilter, UsernamePasswordAuthenticationFilter.class)
                  .build();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
   }

    @Bean
    AuthenticationManager authenticationManager(HttpSecurity httpSecurity, PasswordEncoder passwordEncoder) throws Exception {
    	 return httpSecurity.getSharedObject(AuthenticationManagerBuilder.class)
                 .userDetailsService(userDetailsService)
                 .passwordEncoder(passwordEncoder)
                 .and().build();
    }
}
