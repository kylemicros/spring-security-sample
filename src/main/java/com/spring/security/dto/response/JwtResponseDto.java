package com.spring.security.dto.response;

import java.util.List;

import lombok.Builder;

@Builder
public record JwtResponseDto(
		Long id,
		String username,
		String tokenType,
		String refreshToken,
		String email,
		List<String> roles) {

}
