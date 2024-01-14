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
    @PatchMapping
    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @RequestMapping(value = "/users/logical-delete", method = RequestMethod.PATCH)
    public void logicalDeleteUser(String username, String email) {
        userService.logicalDeleteUser(username, email);
    }

    @DeleteMapping
    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @RequestMapping(value = "/users/delete", method = RequestMethod.DELETE)
    public void deleteUserByIdAndUsername(Long id, String username) {
        userService.deleteUserByIdAndUsername(id, username);
    }
    @GetMapping
    @PreAuthorize(("hasRole('ROLE_ADMIN)"))
    @RequestMapping(value = "/users/get-all-users", method = RequestMethod.GET)
    public List<User> getAllUsers() {
        return userService.getAllUsers();
    }
}
