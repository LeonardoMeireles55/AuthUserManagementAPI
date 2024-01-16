package com.leonardo.auth.spring.service;

import com.leonardo.auth.spring.component.BCryptEncoderComponent;
import com.leonardo.auth.spring.domain.User;
import com.leonardo.auth.spring.enums.UserRoles;
import com.leonardo.auth.spring.infra.exception.ErrorHandling;
import com.leonardo.auth.spring.record.TokenJwtDTO;
import com.leonardo.auth.spring.repository.CustomUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {
    private final CustomUserRepository customUserRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public void signUp(String userName, String firstName, String lastName, String dateBirth, String email, String password) {
        var passEncoded = BCryptEncoderComponent.encrypt(password);
        var user = new User(userName, firstName, lastName, dateBirth, email, passEncoded);

        customUserRepository.save(user);
    }

    public TokenJwtDTO singIn(String username, String password) {
        var authToken = new UsernamePasswordAuthenticationToken(username, password);
        var auth = authenticationManager.authenticate(authToken);

        var token = jwtService.generateToken((User) auth.getPrincipal());

        return new TokenJwtDTO(token);
    }

    public void passwordUpdate(String firstName, String email, String currentPassword, String newPassword) {
        var userCurrentPassword = customUserRepository.getReferenceByFirstNameAndEmail(firstName, email);
        if (!BCryptEncoderComponent
                .decryptMatches
                        (currentPassword, userCurrentPassword.getPassword())
                || BCryptEncoderComponent.decryptMatches(newPassword, userCurrentPassword.getPassword())) {
            throw new ErrorHandling.PasswordNotMatchesException();
        } else {
            customUserRepository
                    .setPasswordWhereByUsername(userCurrentPassword.getUsername(),
                            BCryptEncoderComponent.encrypt(newPassword));
        }
    }

    public void softDeletion(Long id) {
        customUserRepository.softDeletion(id);
    }

    public void hardDeletion(Long id) {
        customUserRepository.deleteById(id);
    }

    public List<User> getAllUsers() {
        return customUserRepository.findAll();
    }

    public void updateUserRoles(Long id, String userRoles) {
        switch (userRoles.trim()) {
            case "ADMIN" -> customUserRepository.updateUserRoles(id, UserRoles.ADMIN);
            case "PREMIUM" -> customUserRepository.updateUserRoles(id, UserRoles.PREMIUM);
            case "FREE" -> customUserRepository.updateUserRoles(id, UserRoles.FREE);
            default -> throw new IllegalArgumentException("User role not recognized: " + userRoles);
        }
    }

    public void toggleAccountNonExpiredById(Long id) {
        customUserRepository.toggleAccountNonExpired(id);
    }

    public void toggleAccountNonLockedById(Long id) {
        customUserRepository.toggleAccountNonLockedById(id);
    }
    public void toggleCredentialsNonExpiredById(Long id) {
        customUserRepository.credentialsNonExpired(id);
    }

    public void toggleEnabledById(Long id) {
        customUserRepository.toggleEnabledById(id);
    }
}

