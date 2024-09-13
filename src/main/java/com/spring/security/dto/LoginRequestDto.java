package com.spring.security.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record LoginRequestDto(
		@NotBlank String username,
		@NotBlank String password) {

}
