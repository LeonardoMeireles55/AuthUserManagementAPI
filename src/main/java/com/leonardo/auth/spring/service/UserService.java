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

    public User signUp(String userName, String firstName, String lastName, String dateBirth, String email, String password) {
        var passEncoded = BCryptEncoderComponent.encrypt(password);
        var user = new User(userName, firstName, lastName, dateBirth, email, passEncoded);

        return customUserRepository.save(user);
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

    public void logicalDeleteUser(String username, String email) {
        var userToDisable = customUserRepository.getReferenceByFirstNameAndEmail(username, email);
        if (userToDisable == null) {
            throw new ErrorHandling.ResourceNotFoundException("user not found");
        }
        customUserRepository.logicalDelete(userToDisable.getUsername());
    }

    public void deleteUserByIdAndUsername(Long id, String username) {
        customUserRepository.deleteByIdAndUsername(id, username);
    }

    public List<User> getAllUsers() {
        return customUserRepository.findAll();
    }
    public void updateUserRoles(String username, String userRoles) {
        switch (userRoles.trim()) {
            case "ADMIN" -> customUserRepository.updateUserRoles(username, UserRoles.ADMIN);
            case "PREMIUM" -> customUserRepository.updateUserRoles(username, UserRoles.PREMIUM);
            case "FREE" -> customUserRepository.updateUserRoles(username, UserRoles.FREE);
            default -> throw new IllegalArgumentException("User role not recognized: " + userRoles);
        }
    }
}
