package com.spring.security.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record ChangeUsernameRequestDto(
		@NotBlank(message = "Please provide a new username!") String newUsername,
		@NotBlank(message = "Please provide the password.") String password) {

}
