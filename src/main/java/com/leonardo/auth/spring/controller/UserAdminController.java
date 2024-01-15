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
public class UserAdminController {

    private final UserService userService;
    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @PatchMapping("/users/logical-delete")
    public void logicalDeleteUser(String username, String email) {
        userService.logicalDeleteUser(username, email);
    }

    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @DeleteMapping("/users/delete")
    public void deleteUserByIdAndUsername(Long id, String username) {
        userService.deleteUserByIdAndUsername(id, username);
    }
    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @GetMapping("/users/get-all-users")
    public List<User> getAllUsers() {
        return userService.getAllUsers();
    }
    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @PatchMapping("/users/roles/update")
    public void updateUserRoles(String username, String userRoles) {
        userService.updateUserRoles(username, userRoles);
    }
}
