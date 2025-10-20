package com.example.backend.security;

import io.jsonwebtoken.*; import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value; import org.springframework.stereotype.Component;
import java.security.Key; import java.time.Instant; import java.util.Date;

@Component
public class JwtTokenProvider {
    private final Key key;
    private final long accessExpMillis;
    private final long refreshExpMillis;

    public JwtTokenProvider(@Value("${jwt.secret}") String secret,
                            @Value("${jwt.access-exp-minutes}") long accessExpMinutes,
                            @Value("${jwt.refresh-exp-days}") long refreshExpDays) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
        this.accessExpMillis = accessExpMinutes * 60 * 1000L;
        this.refreshExpMillis = refreshExpDays * 24 * 60 * 60 * 1000L;
    }

    public String generateAccessToken(String userid, String role, String aud) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(userid)
                .setAudience(aud)           // 앱 식별
                .claim("role", role)
                .setIssuedAt(Date.from(now))
                .setExpiration(new Date(System.currentTimeMillis() + accessExpMillis))
                .signWith(key, SignatureAlgorithm.HS256).compact();
    }

    public String generateRefreshToken(String userid, String role, String aud) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(userid)
                .setAudience(aud)
                .claim("role", role)
                .setIssuedAt(Date.from(now))
                .setExpiration(new Date(System.currentTimeMillis() + refreshExpMillis))
                .signWith(key, SignatureAlgorithm.HS256).compact();
    }

    public boolean validate(String token) {
        try { Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token); return true; }
        catch (JwtException | IllegalArgumentException e) { return false; }
    }

    public String getUserid(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody().getSubject();
    }
    public String getRole(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody().get("role", String.class);
    }
    public String getAudience(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody().getAudience();
    }
}