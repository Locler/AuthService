package com.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ValidateResponse {

    private final Long userId;

    private final String role;

    private final boolean valid;
}
