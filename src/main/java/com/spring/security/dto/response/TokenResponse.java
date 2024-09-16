package com.spring.security.dto.response;

import lombok.Builder;

@Builder
public record TokenResponse(
		String accessToken,
		String refreshToken,
		String tokenType) {

}
