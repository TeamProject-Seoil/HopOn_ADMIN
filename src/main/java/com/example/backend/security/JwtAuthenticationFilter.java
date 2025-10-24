// src/main/java/com/example/backend/security/JwtAuthenticationFilter.java
package com.example.backend.security;

import com.example.backend.repository.UserRepository;
import com.example.backend.repository.UserSessionRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String ADMIN_AUD = "ADMIN_APP";

    private final JwtTokenProvider tokenProvider;
    private final UserRepository userRepository;
    private final UserSessionRepository sessionRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        String auth = req.getHeader(HttpHeaders.AUTHORIZATION);
        if (auth != null && auth.startsWith("Bearer ")) {
            String token = auth.substring(7);

            if (tokenProvider.validate(token)) {
                // 1) 요청 헤더의 aud 강제 확인(관리자 콘솔이 아니면 인증 세팅 안 함)
                String reqAud = req.getHeader("X-Client-Type");
                if (!ADMIN_AUD.equals(reqAud)) {
                    chain.doFilter(req, res);
                    return;
                }

                // 2) 토큰 aud 검증
                String tokenAud = tokenProvider.getAudience(token);
                if (!ADMIN_AUD.equals(tokenAud)) {
                    chain.doFilter(req, res);
                    return;
                }

                // 3) 세션 대조(핵심)
                String userid = tokenProvider.getUserid(token);
                Long sid = tokenProvider.getSessionId(token);
                String ver = tokenProvider.getVersion(token); // 토큰 내 ver(해시 프린트)
                String deviceId = tokenProvider.getDeviceId(token);

                if (sid == null || ver == null || deviceId == null) {
                    chain.doFilter(req, res);
                    return;
                }

                // user를 fetch join으로 함께 로딩 → LAZY 예외 방지
                var sessOpt = sessionRepository.findByIdFetchUser(sid);
                if (sessOpt.isEmpty()) {
                    chain.doFilter(req, res);
                    return;
                }

                var sess = sessOpt.get();
                if (sess.isRevoked()
                        || sess.getExpiresAt() == null
                        || sess.getExpiresAt().isBefore(java.time.LocalDateTime.now())
                        || !ADMIN_AUD.equals(sess.getClientType())
                        || !deviceId.equals(sess.getDeviceId())
                        || !userid.equals(sess.getUser().getUserid())) {
                    chain.doFilter(req, res);
                    return;
                }

                // ✅ ver 비교: DB의 refreshTokenHash 프린트와 토큰 ver가 다르면 이전 토큰 → 무효
                String currentVer = shortVer(sess.getRefreshTokenHash());
                if (!ver.equals(currentVer)) {
                    chain.doFilter(req, res);
                    return;
                }

                var opt = userRepository.findByUserid(userid);
                if (opt.isPresent()) {
                    var user = opt.get();
                    String role = user.getRole().name();
                    if (!"ROLE_ADMIN".equals(role)) {
                        chain.doFilter(req, res);
                        return;
                    }

                    var authentication = new UsernamePasswordAuthenticationToken(
                            userid, null, List.of(new SimpleGrantedAuthority(role)));
                    authentication.setDetails(
                            new org.springframework.security.web.authentication.WebAuthenticationDetailsSource()
                                    .buildDetails(req));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }

        chain.doFilter(req, res);
    }

    private String shortVer(String refreshHash) {
        if (refreshHash == null)
            return "";
        return refreshHash.length() <= 16 ? refreshHash : refreshHash.substring(0, 16);
    }
}
