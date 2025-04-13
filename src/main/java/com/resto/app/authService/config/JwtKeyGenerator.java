package com.resto.app.authService.config;

import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Base64;

public class JwtKeyGenerator {

    public static void main(String[] args) {
        // Generar una clave segura para HS256
        SecretKey key = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS256);
        // Convertir la clave a una cadena en formato Base64
        String base64Key = Base64.getEncoder().encodeToString(key.getEncoded());
        System.out.println("Clave secreta (Base64): " + base64Key);
    }
}
