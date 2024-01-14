package com.leonardo.auth.spring.record;

public record UserPasswordUpdateDTO(
        String firstName,
        String email,
        String currentPassword,
        String newPassword
) {

}
