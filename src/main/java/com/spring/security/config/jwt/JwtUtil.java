package com.spring.security.config.jwt;

import java.util.Date;

import javax.crypto.SecretKey;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.spring.security.config.service.UserPrincipal;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.Jwts.SIG;

@Component
public class JwtUtil {
	private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

	@Value("${security.jwt.secret-key}")
	private String jwtSecret;

	@Value("${security.jwt.expiration-ms}")
	private int jwtExpirationMs;

	@Value("${security.jwt.cookie-name}")
	private String jwtCookie;

	@Value("${security.jwt.refresh-token}")
	private String jwtRefreshToken;

	public String generateToken(Authentication authentication) {
		UserPrincipal userPrincipalImpl = (UserPrincipal) authentication.getPrincipal();

		return Jwts.builder()
				.subject(userPrincipalImpl.getUsername())
				.issuedAt(new Date())
				.expiration(new Date((new Date()).getTime() + jwtExpirationMs * 1000))
				.signWith(key(), SIG.HS256)
				.compact();
	}

	private SecretKey key() {
		return SIG.HS256.key().build();
	}

	public String getUsernameFromJwt(String token) {
		return Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload().getSubject();
	}

	public boolean validateJwt(String token) {
		try {
			Jwts.parser().verifyWith(key()).build().parseSignedClaims(token);
			return true;
		} catch (MalformedJwtException exc) {
			logger.error("Invalid JWT token {}", exc.getMessage());
		} catch (ExpiredJwtException exc) {
			logger.error("JWT token is expired {}", exc.getMessage());
		} catch (UnsupportedJwtException exc) {
			logger.error("JWT token is unsupported {}", exc.getMessage());
		} catch (IllegalArgumentException exc) {
			logger.error("JWT claims string is empty {}", exc.getMessage());
		}

		return false;
	}
}
