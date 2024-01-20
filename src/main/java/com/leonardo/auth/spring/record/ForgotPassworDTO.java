package com.leonardo.auth.spring.record;

import jakarta.validation.constraints.NotBlank;

public record ForgotPassworDTO(
    @NotBlank
    String email
) {
    
}
