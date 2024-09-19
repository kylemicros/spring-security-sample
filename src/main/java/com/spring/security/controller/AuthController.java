package com.spring.security.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.spring.security.dto.ChangePasswordRequestDto;
import com.spring.security.dto.ChangeUsernameRequestDto;
import com.spring.security.dto.LoginRequestDto;
import com.spring.security.dto.SignupRequestDto;
import com.spring.security.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping(path = "/api/auth")
@AllArgsConstructor
public class AuthController {
	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

	private final AuthService authService;

	// @Autowired
	// public AuthController(AuthService authService) {
	// this.authService = authService;
	// }

	@PostMapping(path = "/signup", consumes = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> signup(@Valid @RequestBody SignupRequestDto signupRequestDto) {
		return authService.signup(signupRequestDto);
	}

	@PostMapping(path = "/login", consumes = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> login(@Valid @RequestBody LoginRequestDto loginRequestDto) {
		logger.info("Attempting login...");

		return authService.verify(loginRequestDto);
	}

	@PostMapping(path = "/logout")
	public ResponseEntity<?> logout() {
		logger.info("Attempting logout...");

		return authService.logout();
		// return ResponseEntity.status(HttpStatus.OK).body("Test");
	}

	@PostMapping(path = "/refresh-token")
	public ResponseEntity<?> refreshToken(HttpServletRequest request) {
		logger.info("Attempting to refresh token...");

		return authService.refreshToken(request);
	}

	@PutMapping(path = "/change-username")
	public ResponseEntity<?> changeUsername(@Valid @RequestBody ChangeUsernameRequestDto changeUsernameRequestDto) {
		logger.info("Attempting to change username...");

		// return ResponseEntity.status(HttpStatus.OK).body("Test");
		return authService.updateUsername(changeUsernameRequestDto);
	}

	@PutMapping(path = "/change-password")
	public ResponseEntity<?> changePassword(@Valid @RequestBody ChangePasswordRequestDto changePasswordRequestDto) {
		logger.info("Attempting to change password...");

		return authService.changePassword(changePasswordRequestDto);
	}
}
