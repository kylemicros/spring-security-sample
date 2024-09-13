package com.spring.security.model;

import com.spring.security.model.enums.Roles;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "user_role")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RoleId {
	@Id
	@GeneratedValue(strategy = GenerationType.SEQUENCE)
	private Long id;

	@Enumerated(EnumType.STRING)
	@Column(name = "roles")
	private Roles roles;
}
