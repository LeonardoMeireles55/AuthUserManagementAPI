package com.leonardo.auth.spring.service;

import com.leonardo.auth.spring.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class JwtService {

    private final JwtEncoder jwtEncoder;

    public String generateToken(User userAuthenticated) {
        Instant now = Instant.now();
        long expiry = 36000L;

        String scope = userAuthenticated
                .getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors
                        .joining(""));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("auth-spring")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiry))
                .subject(userAuthenticated.getUsername())
                .claim("scope", scope)
                .build();

        return jwtEncoder.encode(
                        JwtEncoderParameters.from(claims))
                .getTokenValue();
    }

}
