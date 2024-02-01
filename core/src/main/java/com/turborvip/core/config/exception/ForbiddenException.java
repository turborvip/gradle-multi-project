package com.turborvip.core.config.exception;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

@Getter
@Setter
public class ForbiddenException extends RuntimeException{
    private String message;

    private static final HttpStatus status = HttpStatus.BAD_REQUEST;

    public ForbiddenException(String message) {
        this.message = message;
    }
}
