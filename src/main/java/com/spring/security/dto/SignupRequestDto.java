package com.spring.security.dto;

import java.util.Set;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record SignupRequestDto(
		@NotEmpty String firstName,
		@NotEmpty String lastName,
		@NotEmpty @Email String email,
		@NotNull String mobileNumber,
		@NotEmpty String username,
		@NotEmpty @Size(min = 8, max = 16) String password,
		@NotNull Set<String> roles) {

}
