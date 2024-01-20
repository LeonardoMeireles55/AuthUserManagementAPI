package com.leonardo.auth.spring.service;


import com.leonardo.auth.spring.component.BCryptEncoderComponent;
import com.leonardo.auth.spring.domain.ForgotPassword;
import com.leonardo.auth.spring.domain.User;
import com.leonardo.auth.spring.enums.UserRoles;
import com.leonardo.auth.spring.infra.exception.ErrorHandling;
import com.leonardo.auth.spring.record.EmailDTO;
import com.leonardo.auth.spring.record.TokenJwtDTO;
import com.leonardo.auth.spring.repository.ForgotPasswordRepositoryCustom;
import com.leonardo.auth.spring.repository.UserRepositoryCustom;
import lombok.RequiredArgsConstructor;


import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.UUID;


@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepositoryCustom userRepositoryCustom;
    private final ForgotPasswordRepositoryCustom forgotPasswordRepositoryCustom;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final EmailService emailService;

    public List<User> getAllUsers() {
        return userRepositoryCustom.findAll();
    }

    public void signUp(String userName, String firstName, String lastName, String dateBirth, String email,
                       String password) {
        var passEncoded = BCryptEncoderComponent.encrypt(password);
        var user = new User(userName, firstName, lastName, dateBirth, email, passEncoded);

        userRepositoryCustom.save(user);
    }

    public void generateForgotPassword(String email) {
        if (!userRepositoryCustom.existsByEmail(email)) {
            throw new ErrorHandling.ResourceNotFoundException("User not exists");
        }
        var userCurrentPassword = userRepositoryCustom.getReferenceByEmail(email);
        String recoveryToken = UUID.randomUUID().toString();
        ForgotPassword forgotPassword = new ForgotPassword(userCurrentPassword.getEmail(), recoveryToken);
        var emailDTO = new EmailDTO(email, "recovery", recoveryToken);

        forgotPasswordRepositoryCustom.save(forgotPassword);

        emailService.sendEmail(emailDTO);
    }

    public void forgotPasswordUpdate(String username, String email, String password, String newPassword) {
        var userCurrentPassword = userRepositoryCustom.getReferenceByUsername(username);
        var userRecoveryPassword = forgotPasswordRepositoryCustom.getReferenceByUserEmail(email);

        if (!userRecoveryPassword.getUserPassword().trim().equals(password.trim())) {
            throw new ErrorHandling.PasswordNotMatchesException();
        }
        userRepositoryCustom
                .setPasswordWhereByUsername(userCurrentPassword.getUsername(),
                        BCryptEncoderComponent.encrypt(newPassword));
    }

    public TokenJwtDTO singIn(String username, String password) {
        var authToken = new UsernamePasswordAuthenticationToken(username, password);
        var auth = authenticationManager.authenticate(authToken);

        var token = jwtService.generateToken((User) auth.getPrincipal());

        return new TokenJwtDTO(token);
    }

    public void passwordUpdate(String username, String currentPassword, String newPassword) {
        var userCurrentPassword = userRepositoryCustom.getReferenceByUsername(username);
        if (!BCryptEncoderComponent
                .decryptMatches(currentPassword, userCurrentPassword.getPassword())
                || BCryptEncoderComponent.decryptMatches(newPassword, userCurrentPassword.getPassword())) {
            throw new ErrorHandling.PasswordNotMatchesException();
        } else {
            userRepositoryCustom
                    .setPasswordWhereByUsername(userCurrentPassword.getUsername(),
                            BCryptEncoderComponent.encrypt(newPassword));
        }
    }

    public void softDeletion(Long id) {
        if (!forgotPasswordRepositoryCustom.existsById(id)) {
            userRepositoryCustom.softDeletion(id);
        }
        throw new ErrorHandling.NoContentException();
    }

    public void hardDeletion(Long id) {
        if (!forgotPasswordRepositoryCustom.existsById(id)) {
            userRepositoryCustom.deleteById(id);
        }
        throw new ErrorHandling.NoContentException();
    }

    public void updateUserRoles(Long id, String userRoles) {
        if(!userRepositoryCustom.existsById(id)) {
            throw new ErrorHandling.NoContentException();
        }
        switch (userRoles.trim()) {
            case "ADMIN" -> userRepositoryCustom.updateUserRoles(id, UserRoles.ADMIN);
            case "PREMIUM" -> userRepositoryCustom.updateUserRoles(id, UserRoles.PREMIUM);
            case "FREE" -> userRepositoryCustom.updateUserRoles(id, UserRoles.FREE);
            default -> throw new IllegalArgumentException("User role not recognized: " + userRoles);
        }
    }

    public void updateUserData(String username, String firstName, String lastName,
                               String email, String userRoles) {

        User existingUser = userRepositoryCustom.getReferenceByUsername(username);
        existingUser.setFirstName(firstName);
        existingUser.setLastName(lastName);
        existingUser.setEmail(email);
        switch (userRoles.trim()) {
            case "ADMIN" -> existingUser.setUserRoles(UserRoles.ADMIN);
            case "PREMIUM" -> existingUser.setUserRoles(UserRoles.PREMIUM);
            case "FREE" -> existingUser.setUserRoles(UserRoles.FREE);
            default -> throw new IllegalArgumentException("User role not recognized: " + userRoles);
        }
        userRepositoryCustom.save(existingUser);
    }

    public void toggleAccountNonExpiredById(Long id) {
        userRepositoryCustom.toggleAccountNonExpired(id);
    }
    public void toggleAccountNonLockedById(Long id) {
        userRepositoryCustom.toggleAccountNonLockedById(id);
    }
    public void toggleCredentialsNonExpiredById(Long id) {
        userRepositoryCustom.credentialsNonExpired(id);
    }
    public void toggleEnabledById(Long id) {
        userRepositoryCustom.toggleEnabledById(id);
    }

}
