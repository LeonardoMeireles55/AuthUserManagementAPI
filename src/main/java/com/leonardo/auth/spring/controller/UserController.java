package com.leonardo.auth.spring.controller;

import com.leonardo.auth.spring.record.SignInDTO;
import com.leonardo.auth.spring.record.TokenJwtDTO;
import com.leonardo.auth.spring.record.UserDTO;
import com.leonardo.auth.spring.record.UserPasswordUpdateDTO;
import com.leonardo.auth.spring.service.JwtService;
import com.leonardo.auth.spring.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final AuthenticationManager manager;
    private final JwtService jwtService;

    @Transactional
    @PostMapping
    @RequestMapping(value = "/sign-up", method = RequestMethod.POST)
    public ResponseEntity<Void> signUp
            (@RequestBody UserDTO userDTO, UriComponentsBuilder uriComponentsBuilder) {
        var user = userService
                .signUp(userDTO.username(), userDTO.firstName(), userDTO.LastName(),
                        userDTO.dateBirth(), userDTO.email(), userDTO.password());
        var uri = uriComponentsBuilder.path("/user/{id}").buildAndExpand(user.getId()).toUri();
        return ResponseEntity.noContent().build();
    }

    @PostMapping
    @RequestMapping(value = "/sign-in", method = RequestMethod.POST)
    public ResponseEntity<TokenJwtDTO> singIn(@RequestBody SignInDTO signInDTO) {
        var signInJwt = userService.singIn(signInDTO.username(), signInDTO.password());
        return ResponseEntity.ok().body(signInJwt);
    }

    @Transactional
    @PatchMapping
    @RequestMapping(value = "/password/update", method = RequestMethod.PATCH)
    public ResponseEntity<Void>
    updatePassword(@RequestBody UserPasswordUpdateDTO userPasswordUpdateDTO, String newPassword) {
        userService.passwordUpdate(userPasswordUpdateDTO.firstName(), userPasswordUpdateDTO.email(),
                userPasswordUpdateDTO.currentPassword(),
                userPasswordUpdateDTO.newPassword());
        return ResponseEntity.noContent().build();
    }
}