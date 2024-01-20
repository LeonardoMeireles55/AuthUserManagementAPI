package com.leonardo.auth.spring.record;

import jakarta.validation.constraints.NotBlank;

public record SignInDTO(
        @NotBlank
        String username,
        @NotBlank
        String password
) {
}
