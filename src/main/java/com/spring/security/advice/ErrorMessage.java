package com.spring.security.advice;

import java.util.Date;

import lombok.Builder;

@Builder
public record ErrorMessage(
		int statusCode,
		Date timestamp,
		String message,
		String description) {

}
