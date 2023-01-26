package com.eldorado.microservico.autenticacao.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class JwtDto {
    private String token;
    private String userName;
    private String email;

}
