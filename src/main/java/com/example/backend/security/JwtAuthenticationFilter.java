// src/main/java/com/example/backend/security/JwtAuthenticationFilter.java
package com.example.backend.security;

import com.example.backend.repository.UserRepository;
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

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        // 0) 헤더에서 토큰 추출
        String auth = req.getHeader(HttpHeaders.AUTHORIZATION);
        if (auth != null && auth.startsWith("Bearer ")) {
            String token = auth.substring(7);

            // 1) 토큰 파싱/서명 검증
            if (tokenProvider.validate(token)) {
                // 2) 헤더 aud 강제: 요청이 관리자 콘솔에서 온 것인지
                String reqAud = req.getHeader("X-Client-Type");
                if (!ADMIN_AUD.equals(reqAud)) {
                    // 콘솔이 아닌 요청 → 인증 세팅하지 않음(최종적으로 401/403)
                    chain.doFilter(req, res);
                    return;
                }

                // 3) 토큰 aud 검증
                String tokenAud = tokenProvider.getAudience(token);
                if (!ADMIN_AUD.equals(tokenAud)) {
                    chain.doFilter(req, res);
                    return;
                }

                // 4) 사용자 조회 및 ROLE_ADMIN 확인
                String userid = tokenProvider.getUserid(token);
                var opt = userRepository.findByUserid(userid);
                if (opt.isPresent()) {
                    var user = opt.get();
                    String role = user.getRole().name();
                    if (!"ROLE_ADMIN".equals(role)) {
                        // 관리자 권한 아님 → 인증 세팅하지 않음
                        chain.doFilter(req, res);
                        return;
                    }

                    // 5) 인증 컨텍스트 세팅
                    var authentication = new UsernamePasswordAuthenticationToken(
                            userid, null, List.of(new SimpleGrantedAuthority(role)));
                    // (선택) 요청 정보 부가
                    authentication.setDetails(new org.springframework.security.web.authentication.WebAuthenticationDetailsSource().buildDetails(req));

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }

        chain.doFilter(req, res);
    }
}
