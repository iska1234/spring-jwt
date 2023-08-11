package pe.aaron.bregante.jwt.security;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JwtUtil {
		
	@Value("${jwt.secret.key}")
	private String secretKey;	
	
	@Value("${jwt.time.expiration}")
	private String timeExpiration;
	
	public String generateAccesToken(String username) {
		return Jwts.builder()
				.setSubject(username)
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + Long.parseLong(timeExpiration)))
				.signWith(getSignature(),SignatureAlgorithm.HS256)
				.compact();		
	}
	
	public boolean isTokenValid(String token)
	{
		try {
			Jwts.parserBuilder()
			.setSigningKey(getSignature())
			.build()
			.parseClaimsJws(token)
			.getBody();
			
			return true;
			
		} catch (Exception e) {
		   log.error("Token invalido, error:".concat(e.getMessage()));
		   return false;
		}
	}

	public String getUsernameFromToken(String token )
	{
		return getClaim(token,Claims::getSubject);
	}
	
	public <T> T getClaim(String token, Function<Claims, T> claimsFunction) {
		Claims claims = extracAllClaims(token);
		return claimsFunction.apply(claims);
	}
	
	public Claims extracAllClaims(String token)
	{
		return Jwts.parserBuilder()
				.setSigningKey(getSignature())
				.build()
				.parseClaimsJws(token)
				.getBody();
	}
	
	
	
	public Key getSignature() {
		byte[] keyBytes = Decoders.BASE64.decode(secretKey);		
		return Keys.hmacShaKeyFor(keyBytes);		
	}
	

}
