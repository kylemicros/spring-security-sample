package com.spring.security.config.service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.spring.security.model.Token;
import com.spring.security.repository.TokenRepository;
import com.spring.security.repository.UserRepository;
import com.spring.security.service.exception.TokenRefreshException;

@Service
public class RefreshTokenService {
	@Value("${security.jwt.refresh-token-expiration}")
	private Long refreshTokenDurationMs;

	private final TokenRepository tokenRepository;
	private final UserRepository userRepository;

	@Autowired
	public RefreshTokenService(TokenRepository tokenRepository, UserRepository userRepository) {
		this.tokenRepository = tokenRepository;
		this.userRepository = userRepository;
	}

	public Optional<Token> findByToken(String token) {
		return tokenRepository.findByToken(token);
	}

	public Token createRefreshToken(Long id) {
		Token token = new Token();

		token.setUser(userRepository.findById(id).get());
		token.setExpirationDate(Instant.now().plusMillis(refreshTokenDurationMs));
		token.setToken(UUID.randomUUID().toString());

		token = tokenRepository.save(token);
		return token;
	}

	public Token verifyExpiration(Token token) {
		if (token.getExpirationDate().compareTo(Instant.now()) < 0) {
			tokenRepository.delete(token);

			throw new TokenRefreshException(token.getToken(), "Token has expired. Please signin again.");
		}

		return token;
	}

	public Long deleteByUserId(Long id) {
		return tokenRepository.deleteByUser(userRepository.findById(id).get());
	}
}
