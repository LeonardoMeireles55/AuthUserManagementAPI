package com.leonardo.auth.spring.record;

import jakarta.validation.constraints.NotBlank;

public record EmailDTO(
    @NotBlank
    String to,
    @NotBlank
    String subject,
    @NotBlank
    String body
) {
    
}
