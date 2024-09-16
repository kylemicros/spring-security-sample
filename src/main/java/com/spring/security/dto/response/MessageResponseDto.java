package com.spring.security.dto.response;

import lombok.Builder;

@Builder
public record MessageResponseDto(
		String message) {

}
