package com.leonardo.auth.spring.record;

import jakarta.validation.constraints.NotBlank;

public record UserPasswordUpdateDTO(
        @NotBlank
        String username,
        @NotBlank
        String currentPassword,
        @NotBlank
        String newPassword
) {

}
