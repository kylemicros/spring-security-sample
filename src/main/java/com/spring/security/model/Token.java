package com.spring.security.model;

import java.time.Instant;

import com.spring.security.model.enums.TokenType;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name = "tokens", indexes = {
		@Index(name = "token_name_idx", columnList = "token"),
		@Index(name = "expiration_date_idx", columnList = "expiration_date")
})
@NoArgsConstructor
@AllArgsConstructor
public class Token {
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;

	@Enumerated(EnumType.STRING)
	private TokenType tokenType = TokenType.BEARER;

	@OneToOne
	@JoinColumn(name = "user_id")
	private User user;

	@Column(name = "token", unique = true)
	private String token;

	@Column(name = "expiration_date")
	private Instant expirationDate;

}
