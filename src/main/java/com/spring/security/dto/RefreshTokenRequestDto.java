package com.spring.security.dto;

import java.time.Instant;

import com.spring.security.model.enums.TokenType;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;

@Builder
public record RefreshTokenRequestDto(
		@NotNull Long id,
		@NotNull String username,
		@NotNull TokenType tokenType,
		@NotBlank String token,
		@NotBlank Instant expirationDate) {

}
