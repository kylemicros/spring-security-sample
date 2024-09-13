package com.spring.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.spring.security.config.jwt.AuthEntryPointJwt;
import com.spring.security.config.jwt.AuthTokenFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private AuthEntryPointJwt entryPointJwt;

	@Bean
	public AuthTokenFilter authTokenFilter() {
		return new AuthTokenFilter();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
	}

	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailsService);
		authenticationProvider.setPasswordEncoder(passwordEncoder());

		return authenticationProvider;
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		return http
				.csrf((csrf) -> csrf.ignoringRequestMatchers("/api/auth/**"))
				.authorizeHttpRequests((authz) -> authz
						.requestMatchers("/api/user/**").permitAll()
						.requestMatchers("/api/auth/**").permitAll()
						.anyRequest().authenticated())
				.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.httpBasic(withDefaults())
				.logout((logout) -> logout
						.logoutUrl("/logout")
						.logoutSuccessUrl("/login?logout"))
				.exceptionHandling((exc) -> exc
						.authenticationEntryPoint(entryPointJwt))
				.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class)
				.build();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
		return authConfig.getAuthenticationManager();
	}
}
