package com.dtos;

import com.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ValidateResponse {

    private final Long userId;

    private final Role role;

    private final boolean valid;
}
