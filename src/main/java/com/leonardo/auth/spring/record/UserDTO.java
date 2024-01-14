package com.leonardo.auth.spring.record;

public record UserDTO(
        String username,
        String firstName,
        String LastName,
        String dateBirth,
        String email,
        String password
) {
}