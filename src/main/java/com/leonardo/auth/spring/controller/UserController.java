package com.leonardo.auth.spring.controller;

import com.leonardo.auth.spring.record.ForgotPassworDTO;
import com.leonardo.auth.spring.record.RecoveryForgotPasswordDTO;
import com.leonardo.auth.spring.record.SignInDTO;
import com.leonardo.auth.spring.record.TokenJwtDTO;
import com.leonardo.auth.spring.record.UserDTO;
import com.leonardo.auth.spring.record.UserPasswordUpdateDTO;
import com.leonardo.auth.spring.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @Transactional
    @PostMapping("/signUp")
    public ResponseEntity<Void> signUp
        (@RequestBody UserDTO userDTO) {
            userService.signUp(userDTO.username(), userDTO.firstName(), userDTO.LastName(),
                    userDTO.dateBirth(), userDTO.email(), userDTO.password());
                return ResponseEntity.noContent().build();
    }

    @PostMapping("/signIn")
    public ResponseEntity<TokenJwtDTO> singIn(@RequestBody SignInDTO signInDTO) {
        var signInJwt = userService.singIn(signInDTO.username(), signInDTO.password());
            return ResponseEntity.ok().body(signInJwt);
    }

    @Transactional
    @PatchMapping("/password/update")
    public ResponseEntity<Void>
    updatePassword(@Valid @RequestBody UserPasswordUpdateDTO userPasswordUpdateDTO, String newPassword) {
        userService.passwordUpdate(userPasswordUpdateDTO.firstName(),
                userPasswordUpdateDTO.email(), userPasswordUpdateDTO.currentPassword(),
                userPasswordUpdateDTO.newPassword());
            return ResponseEntity.noContent().build();
    }

    @PostMapping("password/forgotPassword")
    public void forgotPassword(@Valid @RequestBody ForgotPassworDTO forgotPassworDTO) {
        userService.forgotPassword(forgotPassworDTO.email());
    }

    @PatchMapping("password/recoveryForgotPassword")
    public void recoveryForgotPassword(@Valid @RequestBody RecoveryForgotPasswordDTO forgotPasswordDTO) {
        userService.forgotPasswordUpdate(forgotPasswordDTO.username(), forgotPasswordDTO.email(), forgotPasswordDTO.token(), forgotPasswordDTO.newPassword());
    }
}