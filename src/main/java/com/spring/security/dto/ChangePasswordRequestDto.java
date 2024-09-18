package com.spring.security.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record ChangePasswordRequestDto(
		@NotBlank String newPassword,
		@NotBlank @Size(min = 8, message = "The password must be at least 8 characters long!") String currentPassword) {

}
