package com.spring.security.config.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import com.spring.security.config.service.UserPrincipal;
import com.spring.security.model.User;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;

@Component
public class JwtUtil {
	private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

	@Value("${security.jwt.secret-key}")
	private String jwtSecret;

	@Value("${security.jwt.expiration-ms}")
	private int jwtExpirationMs;

	@Value("${security.jwt.cookie-name}")
	private String jwtCookie;

	@Value("${security.jwt.cookie-refresh-name}")
	private String jwtRefreshCookie;

	public ResponseCookie generateJwtCookie(UserPrincipal userPrincipal) {
		String jwtToken = generateToken(userPrincipal.getUsername());
		return generateCookie(jwtCookie, jwtToken, "/api");
	}

	public ResponseCookie generateJwtCookie(User user) {
		String jwtToken = generateToken(user.getUsername());
		return generateCookie(jwtCookie, jwtToken, "/api");
	}

	public ResponseCookie generateRefreshJwtCookie(String refreshToken) {
		return generateCookie(jwtRefreshCookie, refreshToken, "/api/auth/refresh-token");
	}

	public String getJwtFromCookies(HttpServletRequest request) {
		return getCookieValueByName(request, jwtCookie);
	}

	public String getJwtRefreshFromCookies(HttpServletRequest request) {
		return getCookieValueByName(request, jwtRefreshCookie);
	}

	public ResponseCookie getCleanJwtCookie() {
		ResponseCookie cookie = ResponseCookie.from(jwtCookie, null).path("/api").build();
		return cookie;
	}

	public ResponseCookie getCleanJwtRefreshCookie() {
		ResponseCookie cookie = ResponseCookie.from(jwtRefreshCookie, null).path("/api/auth/refresh-token").build();
		return cookie;
	}

	public String generateToken(String username) {
		return Jwts.builder()
				.subject(username)
				.issuedAt(new Date())
				.expiration(new Date((new Date()).getTime() + jwtExpirationMs * 1000))
				.signWith(key())
				.compact();
	}

	private SecretKey key() {
		byte[] keyBytes = Base64.getDecoder()
				.decode(jwtSecret.getBytes(StandardCharsets.UTF_8));

		return new SecretKeySpec(keyBytes, "HmacSHA256");
	}

	public String getUsernameFromJwt(String token) {
		return Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload().getSubject();
	}

	private ResponseCookie generateCookie(String name, String value, String path) {
		ResponseCookie cookie = ResponseCookie.from(name, value)
				.path(path)
				.maxAge(24 * 60 * 60)
				.httpOnly(true)
				.build();

		return cookie;
	}

	private String getCookieValueByName(HttpServletRequest request, String name) {
		Cookie cookie = WebUtils.getCookie(request, name);

		if (cookie != null) {
			return cookie.getValue();
		}

		return null;
	}

	public boolean validateJwt(String token) {
		try {
			Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload();
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
