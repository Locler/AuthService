package com.services;

import com.dtos.LoginRequest;
import com.dtos.RegisterRequest;
import com.dtos.TokenResponse;
import com.dtos.ValidateResponse;
import com.entities.Credential;
import com.repositories.CredentialRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final CredentialRepository repo;
    private final JwtService jwtService;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Transactional
    public void register(RegisterRequest req) {
        repo.findByUsername(req.getUsername()).ifPresent(u -> {
            throw new IllegalArgumentException("Username already exists");
        });

        Credential c = Credential.builder()
                .id(UUID.randomUUID())
                .userId(req.getUserId())
                .username(req.getUsername())
                .passwordHash(passwordEncoder.encode(req.getPassword()))
                .role(req.getRole())
                .build();
        repo.save(c);
    }

    public TokenResponse login(LoginRequest req) {
        Credential cred = repo.findByUsername(req.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("Invalid username or password"));

        if (!passwordEncoder.matches(req.getPassword(), cred.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid username or password");
        }

        Long userId = cred.getUserId();
        // if userId null, we still can encode userId in token as 0 or throw.
        if (userId == null) throw new IllegalArgumentException("Credential is not linked to userId");

        String access = jwtService.generateAccessToken(userId, cred.getRole());
        String refresh = jwtService.generateRefreshToken(userId, cred.getRole());
        return new TokenResponse(access, refresh);
    }

    public TokenResponse refresh(String refreshToken) {
        if (jwtService.validate(refreshToken)) throw new IllegalArgumentException("Invalid refresh token");
        var claims = jwtService.parse(refreshToken).getBody();
        Long userId = Long.valueOf(claims.getSubject());
        String role = claims.get("role", String.class);
        return new TokenResponse(jwtService.generateAccessToken(userId, role), jwtService.generateRefreshToken(userId, role));
    }

    public ValidateResponse validate(String token) {
        if (jwtService.validate(token)) return new ValidateResponse(null, null, false);
        var claims = jwtService.parse(token).getBody();
        Long userId = Long.valueOf(claims.getSubject());
        String role = claims.get("role", String.class);
        return new ValidateResponse(userId, role, true);
    }
}
