package com.leonardo.auth.spring.controller;

import com.leonardo.auth.spring.domain.User;
import com.leonardo.auth.spring.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/admin")
public class AdminController {

    private final UserService userService;

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
}
