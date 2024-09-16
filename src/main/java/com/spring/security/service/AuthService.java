package com.spring.security.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.spring.security.config.jwt.JwtUtil;
import com.spring.security.config.service.RefreshTokenService;
import com.spring.security.config.service.UserPrincipal;
import com.spring.security.dto.LoginRequestDto;
import com.spring.security.dto.SignupRequestDto;
import com.spring.security.dto.response.MessageResponseDto;
import com.spring.security.model.Token;
import com.spring.security.model.User;
import com.spring.security.repository.UserRepository;
import com.spring.security.service.exception.TokenRefreshException;
import com.spring.security.service.mapper.AuthServiceMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;

@Service
public class AuthService {
	private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

	private final AuthenticationManager authenticationManager;
	private final PasswordEncoder encoder;
	private final UserRepository userRepository;
	private final AuthServiceMapper authServiceMapper;
	private final JwtUtil jwtUtil;
	private final RefreshTokenService refreshTokenService;

	@Autowired
	public AuthService(AuthenticationManager authenticationManager, UserRepository userRepository,
			AuthServiceMapper authServiceMapper, PasswordEncoder encoder, JwtUtil jwtUtil,
			RefreshTokenService refreshTokenService) {
		this.authenticationManager = authenticationManager;
		this.userRepository = userRepository;
		this.authServiceMapper = authServiceMapper;
		this.encoder = encoder;
		this.jwtUtil = jwtUtil;
		this.refreshTokenService = refreshTokenService;
	}

	public ResponseEntity<?> signup(SignupRequestDto signupRequestDto) {
		if (userRepository.findByEmail(signupRequestDto.email()).isPresent()) {

			return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already exists!");
		}

		if (userRepository.findByUsername(signupRequestDto.username()).isPresent()) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body("Username is already taken!");
		}

		int passwordLength = signupRequestDto.password().length();
		if (passwordLength < 8) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body("Password must be 8-16 characters long!");
		}

		User user = authServiceMapper.mapSignupToUser(signupRequestDto);
		user.setPassword(encoder.encode(signupRequestDto.password()));

		userRepository.save(user);

		return ResponseEntity.status(HttpStatus.CREATED).body("Successfully registered user");
	}

	public ResponseEntity<?> verify(LoginRequestDto loginRequestDto) {
		Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(loginRequestDto.username(),
						loginRequestDto.password()));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

		ResponseCookie jwtCookie = jwtUtil.generateJwtCookie(userPrincipal);
		Token refreshToken = refreshTokenService.createRefreshToken(userPrincipal.getId());
		ResponseCookie jwtRefreshCookie = jwtUtil.generateRefreshJwtCookie(refreshToken.getToken());

		// String jwt = jwtUtil.generateToken(authentication);

		return ResponseEntity.status(HttpStatus.OK)
				.header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
				.header(HttpHeaders.SET_COOKIE, jwtRefreshCookie.toString())
				.body(new MessageResponseDto("Successfully logged in."));
	}

	@Transactional
	public ResponseEntity<?> logout() {
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		if (!principal.toString().equals("anonymousUser")) {
			Long id = ((UserPrincipal) principal).getId();
			refreshTokenService.deleteByUserId(id);
		}

		// return ResponseEntity.status(HttpStatus.OK).body(principal.toString());
		// if (principal == null || principal.toString().equals("anonymousUser")) {
		// return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
		// .body(new MessageResponseDto("Invalid Request"));
		// }
		//
		// Long id = ((UserPrincipal) principal).getId();
		// refreshTokenService.deleteByUserId(id);
		//
		// Start uncommenting here...
		ResponseCookie jwtCookie = jwtUtil.getCleanJwtCookie();
		ResponseCookie jwtRefreshCookie = jwtUtil.getCleanJwtRefreshCookie();

		return ResponseEntity.status(HttpStatus.OK)
				.header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
				.header(HttpHeaders.SET_COOKIE, jwtRefreshCookie.toString())
				.body(new MessageResponseDto("Successfully logged out."));
		// return ResponseEntity.status(HttpStatus.OK).body(principal);
	}

	public ResponseEntity<?> refreshToken(HttpServletRequest request) {
		String refreshToken = jwtUtil.getJwtRefreshFromCookies(request);

		if ((refreshToken != null) && (refreshToken.length() > 0)) {
			return refreshTokenService.findByToken(refreshToken)
					.map(refreshTokenService::verifyExpiration)
					.map(Token::getUser)
					.map((user) -> {
						ResponseCookie jwtCookie = jwtUtil.generateJwtCookie(user);

						return ResponseEntity.status(HttpStatus.OK)
								.header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
								.body(new MessageResponseDto("Successfully refreshed tokens."));
					})
					.orElseThrow(
							() -> new TokenRefreshException(refreshToken, "Refresh token is not in the database."));
		}

		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Refresh token is empty.");
	}
}
