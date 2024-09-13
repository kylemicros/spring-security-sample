package com.spring.security.service;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.spring.security.config.jwt.JwtUtil;
import com.spring.security.dto.LoginRequestDto;
import com.spring.security.dto.SignupRequestDto;
import com.spring.security.model.User;
import com.spring.security.repository.UserRepository;
import com.spring.security.service.mapper.AuthServiceMapper;

import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class AuthService {
	private final AuthenticationManager authenticationManager;
	private final PasswordEncoder encoder;
	private final UserRepository userRepository;
	private final AuthServiceMapper authServiceMapper;
	private final JwtUtil jwtUtil;

	@Autowired
	public AuthService(AuthenticationManager authenticationManager, UserRepository userRepository,
			AuthServiceMapper authServiceMapper, PasswordEncoder encoder, JwtUtil jwtUtil) {
		this.authenticationManager = authenticationManager;
		this.userRepository = userRepository;
		this.authServiceMapper = authServiceMapper;
		this.encoder = encoder;
		this.jwtUtil = jwtUtil;
	}

	public ResponseEntity<?> signup(SignupRequestDto signupRequestDto) {
		if (userRepository.findByEmail(signupRequestDto.email()).isPresent()) {

			return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already exists!");
		}

		if (userRepository.findByUsername(signupRequestDto.username()).isPresent()) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body("Username is already taken!");
		}

		int passwordLength = signupRequestDto.password().length();
		if (passwordLength < 8 || passwordLength > 16) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body("Password must be 8-16 characters long!");
		}

		User user = authServiceMapper.mapSignupToUser(signupRequestDto);
		user.setPassword(encoder.encode(signupRequestDto.password()));

		userRepository.save(user);

		return ResponseEntity.status(HttpStatus.CREATED).body("Successfully registered user");
	}

	@Transactional
	public ResponseEntity<?> verify(LoginRequestDto loginRequestDto) {
		try {
			Authentication authentication = authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(loginRequestDto.username(),
							loginRequestDto.password()));

			if (!authentication.isAuthenticated()) {
				return new ResponseEntity<>("Invalid username/password. Please try again", HttpStatus.UNAUTHORIZED);
			}

			Map<String, Object> body = new HashMap<>();
			body.put("message", HttpStatus.OK);
			body.put("token", jwtUtil.generateToken(authentication));

			return new ResponseEntity<>(body, HttpStatus.OK);

		} catch (BadCredentialsException exc) {
			return new ResponseEntity<>("Bad Request", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}
}
