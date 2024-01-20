package com.leonardo.auth.spring.record;

import jakarta.validation.constraints.NotBlank;

public record RecoveryForgotPasswordDTO(
    @NotBlank
    String username,
    @NotBlank
    String email,
    @NotBlank
    String token,
    @NotBlank
    String newPassword
) {
    
}
