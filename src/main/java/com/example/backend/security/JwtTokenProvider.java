// src/main/java/com/example/backend/security/JwtTokenProvider.java
package com.example.backend.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Instant;
import java.util.Date;

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

    /** access 토큰: aud, role, deviceId, sid, ver(문자열) 포함 */
    public String generateAccessToken(String userid, String role, String aud,
            String deviceId, Long sessionId, String sessionVerStr) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(userid)
                .setAudience(aud) // 앱 식별
                .claim("role", role)
                .claim("deviceId", deviceId)
                .claim("sid", sessionId)
                .claim("ver", sessionVerStr) // ← 문자열 프린트
                .setIssuedAt(Date.from(now))
                .setExpiration(new Date(System.currentTimeMillis() + accessExpMillis))
                .signWith(key, SignatureAlgorithm.HS256).compact();
    }

    /** refresh 토큰에도 aud/role/deviceId/sid 포함(로깅/검증 유용) */
    public String generateRefreshToken(String userid, String role, String aud,
            String deviceId, Long sessionId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(userid)
                .setAudience(aud)
                .claim("role", role)
                .claim("deviceId", deviceId)
                .claim("sid", sessionId)
                .setIssuedAt(Date.from(now))
                .setExpiration(new Date(System.currentTimeMillis() + refreshExpMillis))
                .signWith(key, SignatureAlgorithm.HS256).compact();
    }

    public boolean validate(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    private Claims claims(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    public String getUserid(String token) {
        return claims(token).getSubject();
    }

    public String getRole(String token) {
        return claims(token).get("role", String.class);
    }

    public String getAudience(String token) {
        return claims(token).getAudience();
    }

    public String getDeviceId(String token) {
        return claims(token).get("deviceId", String.class);
    }

    public Long getSessionId(String token) {
        return claims(token).get("sid", Long.class);
    }

    public String getVersion(String token) {
        return claims(token).get("ver", String.class);
    } // 문자열
}
