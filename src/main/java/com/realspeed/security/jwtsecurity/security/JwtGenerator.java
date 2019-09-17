package com.realspeed.security.jwtsecurity.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.realspeed.security.jwtsecurity.model.JwtUser;

@Component
public class JwtGenerator {
    
	@Value("${jwt.client.secret}")
    private String secret;
	
	public String generate(JwtUser jwtUser) {

        Claims claims = Jwts.claims().setSubject(jwtUser.getUserName());
        claims.put("userId", String.valueOf(jwtUser.getId()));
        claims.put("role", jwtUser.getRole());

        return "Bearer "+Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }
}
