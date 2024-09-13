package com.spring.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.spring.security.model.RoleId;
import com.spring.security.model.enums.Roles;

@Repository
public interface RoleRepository extends JpaRepository<RoleId, Long> {
	Optional<RoleId> findByRoles(Roles roles);
}