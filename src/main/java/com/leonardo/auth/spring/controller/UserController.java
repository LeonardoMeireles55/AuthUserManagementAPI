package com.leonardo.auth.spring.controller;

import com.leonardo.auth.spring.record.SignInDTO;
import com.leonardo.auth.spring.record.TokenJwtDTO;
import com.leonardo.auth.spring.record.UserDTO;
import com.leonardo.auth.spring.record.UserPasswordUpdateDTO;
import com.leonardo.auth.spring.service.UserService;
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
    @PostMapping("/sign-up")
    public ResponseEntity<Void> signUp
        (@RequestBody UserDTO userDTO) {
            userService.signUp(userDTO.username(), userDTO.firstName(), userDTO.LastName(), userDTO.dateBirth(), userDTO.email(), userDTO.password());
                return ResponseEntity.noContent().build();
    }

    @PostMapping("/sign-in")
    public ResponseEntity<TokenJwtDTO> singIn(@RequestBody SignInDTO signInDTO) {
        var signInJwt = userService.singIn(signInDTO.username(), signInDTO.password());
            return ResponseEntity.ok().body(signInJwt);
    }

    @Transactional
    @PatchMapping("/password/update")
    public ResponseEntity<Void>
    updatePassword(@RequestBody UserPasswordUpdateDTO userPasswordUpdateDTO, String newPassword) {
        userService.passwordUpdate(userPasswordUpdateDTO.firstName(), userPasswordUpdateDTO.email(), userPasswordUpdateDTO.currentPassword(),userPasswordUpdateDTO.newPassword());
            return ResponseEntity.noContent().build();
    }
}