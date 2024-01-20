package com.leonardo.auth.spring.controller;

import com.leonardo.auth.spring.domain.User;
import com.leonardo.auth.spring.record.UserUpdateDTO;
import com.leonardo.auth.spring.record.EmailDTO;
import com.leonardo.auth.spring.service.EmailService;
import com.leonardo.auth.spring.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/admin")
public class AdminController {

    private final UserService userService;
    private final EmailService emailService;

    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @PostMapping("/sendEmail")
    public void sendEmail(@Valid @RequestBody EmailDTO email) {
        emailService.sendEmail(email);
    }

    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @PatchMapping("/users/softDeletion")
    public void softDeletion(Long id) {
        userService.softDeletion(id);
    }

    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @PatchMapping("/users/toggleAccountNonExpired")
    public void toggleAccountNonExpiredById(Long id) {
        userService.toggleAccountNonExpiredById(id);
    }

    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @PatchMapping("/users/toggleAccountNonLocked")
    public void toggleAccountNonLockedById(Long id) {
        userService.toggleAccountNonLockedById(id);
    }

    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @PatchMapping("/users/toggleCredentialsNonExpired")
    public void toggleCredentialNonExpiredById(Long id) {
        userService.toggleCredentialsNonExpiredById(id);
    }

    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @PatchMapping("/users/toggleEnabled")
    public void toggleEnabledById(Long id) {
        userService.toggleEnabledById(id);
    }

    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @DeleteMapping("/users/hardDeletion")
    public void deleteUserById(Long id) {
        userService.hardDeletion(id);
    }

    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @GetMapping("/users/getAllUsers")
    public List<User> getAllUsers() {
        return userService.getAllUsers();
    }

    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @PatchMapping("/users/roles/update")
    public void updateUserRoles(Long id, String userRoles) {
        userService.updateUserRoles(id, userRoles);
    }

    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @PutMapping("/users/updateUserData")
    public void updateUserData(UserUpdateDTO userUpdateDTO) {
        userService.updateUserData(userUpdateDTO.currentUsername(), userUpdateDTO.newFirstName(), userUpdateDTO.newLastName(), userUpdateDTO.newEmail(), userUpdateDTO.userRoles());
    }
}
