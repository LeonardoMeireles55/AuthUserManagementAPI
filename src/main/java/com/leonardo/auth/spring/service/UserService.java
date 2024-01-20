package com.leonardo.auth.spring.service;

import com.leonardo.auth.spring.component.BCryptEncoderComponent;
import com.leonardo.auth.spring.domain.ForgotPassword;
import com.leonardo.auth.spring.domain.User;
import com.leonardo.auth.spring.enums.UserRoles;
import com.leonardo.auth.spring.infra.exception.ErrorHandling;
import com.leonardo.auth.spring.record.EmailDTO;
import com.leonardo.auth.spring.record.TokenJwtDTO;
import com.leonardo.auth.spring.repository.CustomForgotPasswordRepository;
import com.leonardo.auth.spring.repository.CustomUserRepository;

import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {
    private final CustomUserRepository customUserRepository;
    private final CustomForgotPasswordRepository customForgotPasswordRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final EmailService emailService;

    public void signUp(String userName, String firstName, String lastName, String dateBirth, String email,
            String password) {
        var passEncoded = BCryptEncoderComponent.encrypt(password);
        var user = new User(userName, firstName, lastName, dateBirth, email, passEncoded);

        customUserRepository.save(user);
    }

    public void forgotPassword(String email) {
        if (!customUserRepository.existsByEmail(email)) {
            throw new ErrorHandling.ResourceNotFoundException("Not exists");
        }
        var userCurrentPassword = customUserRepository.getReferenceByEmail(email);
        String recoveryToken = UUID.randomUUID().toString();
        ForgotPassword forgotPassword = new ForgotPassword(userCurrentPassword.getEmail(), recoveryToken);
        var emailDTO = new EmailDTO(email, "recovery", recoveryToken);

        customForgotPasswordRepository.save(forgotPassword);

        emailService.sendEmail(emailDTO);
    }

    public void forgotPasswordUpdate(String username, String email, String password, String newPassword) {
        var userCurrentPassword = customUserRepository.getReferenceByUsernameAndEmail(username, email);
        var userRecoveryPassoword = customForgotPasswordRepository.getReferenceByUserEmail(email);

        if (!userRecoveryPassoword.getUserPassword().trim().equals(password.trim())) {
            throw new ErrorHandling.PasswordNotMatchesException();
        }
        customUserRepository
                .setPasswordWhereByUsername(userCurrentPassword.getUsername(),
                        BCryptEncoderComponent.encrypt(newPassword));
    }

    public TokenJwtDTO singIn(String username, String password) {
        var authToken = new UsernamePasswordAuthenticationToken(username, password);
        var auth = authenticationManager.authenticate(authToken);

        var token = jwtService.generateToken((User) auth.getPrincipal());

        return new TokenJwtDTO(token);
    }

    public void passwordUpdate(String firstName, String email, String currentPassword, String newPassword) {
        var userCurrentPassword = customUserRepository.getReferenceByUsernameAndEmail(firstName, email);
        if (!BCryptEncoderComponent
                .decryptMatches(currentPassword, userCurrentPassword.getPassword())
                || BCryptEncoderComponent.decryptMatches(newPassword, userCurrentPassword.getPassword())) {
            throw new ErrorHandling.PasswordNotMatchesException();
        } else {
            customUserRepository
                    .setPasswordWhereByUsername(userCurrentPassword.getUsername(),
                            BCryptEncoderComponent.encrypt(newPassword));
        }
    }

    public void softDeletion(Long id) {
        if (!customForgotPasswordRepository.existsById(id)) {
            customUserRepository.softDeletion(id);
        }
        throw new ErrorHandling.NoContentException();
    }

    public void hardDeletion(Long id) {
        if (!customForgotPasswordRepository.existsById(id)) {
            customUserRepository.deleteById(id);
        }
        throw new ErrorHandling.NoContentException();
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
    public void changeValues(String username, String firstName, String lastName,
                             String email, @NotBlank String userRoles) {
        // Recupera o usuário existente pelo username
        User existingUser = customUserRepository.getReferenceByUsernameAndEmail(username, email);
        
        // Atualiza os valores desejados
        existingUser.setFirstName(firstName);
        existingUser.setLastName(lastName);
        existingUser.setEmail(email);
        switch (userRoles.trim()) {
            case "ADMIN" -> existingUser.setUserRoles(UserRoles.ADMIN);
            case "PREMIUM" -> existingUser.setUserRoles(UserRoles.PREMIUM);
            case "FREE" -> existingUser.setUserRoles(UserRoles.FREE);
            default -> throw new IllegalArgumentException("User role not recognized: " + userRoles);
        }
        // Salva as alterações
        customUserRepository.save(existingUser);
    }
}
