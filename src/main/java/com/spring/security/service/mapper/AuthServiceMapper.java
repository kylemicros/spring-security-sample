package com.spring.security.service.mapper;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.spring.security.dto.SignupRequestDto;
import com.spring.security.model.RoleId;
import com.spring.security.model.User;
import com.spring.security.model.enums.Roles;
import com.spring.security.repository.RoleRepository;

@Service
public class AuthServiceMapper {
    private final RoleRepository roleRepository;

    @Autowired
    public AuthServiceMapper(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    public User mapSignupToUser(SignupRequestDto signupRequestDto) {
        User user = new User();

        user.setFirstName(signupRequestDto.firstName());
        user.setLastName(signupRequestDto.lastName());
        user.setEmail(signupRequestDto.email());
        user.setMobileNumber(signupRequestDto.mobileNumber());
        user.setUsername(signupRequestDto.username());

        Set<RoleId> roles = new HashSet<>();
        for (String roleName : signupRequestDto.roles()) {
            Roles role = Roles.valueOf(roleName);
            RoleId roleEntity = roleRepository.findByRoles(role)
                    .orElseThrow(() -> new RuntimeException("Role not found " + role));
            roles.add(roleEntity);
        }

        user.setRoles(roles);

        // Save user
        return user;
    }
}
