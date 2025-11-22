package com.controller;

import com.dtos.LoginRequest;
import com.dtos.RegisterRequest;
import com.dtos.TokenResponse;
import com.dtos.ValidateResponse;
import com.services.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest req) {
        authService.register(req);
        return ResponseEntity.status(201).build();
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest req) {
        return ResponseEntity.ok(authService.login(req));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@RequestParam("refreshToken") String refreshToken) {
        return ResponseEntity.ok(authService.refresh(refreshToken));
    }

    @GetMapping("/validate")
    public ResponseEntity<ValidateResponse> validate(@RequestParam("token") String token) {
        return ResponseEntity.ok(authService.validate(token));
    }
}
