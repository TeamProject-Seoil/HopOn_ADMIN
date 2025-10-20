package com.example.backend.security;

import com.example.backend.repository.UserRepository;
import jakarta.servlet.*; import jakarta.servlet.http.*; 
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException; import java.util.List;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider tokenProvider;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        String auth = req.getHeader(HttpHeaders.AUTHORIZATION);
        if (auth != null && auth.startsWith("Bearer ")) {
            String token = auth.substring(7);
            if (tokenProvider.validate(token)) {
                String tokenAud = tokenProvider.getAudience(token);

                // ⬇️ 간단 aud 검증 (필요 시 프론트에서 X-Client-Type 헤더로 전달)
                String reqAud = req.getHeader("X-Client-Type");
                if (reqAud != null && !reqAud.equals(tokenAud)) {
                    // aud 불일치 → 인증 설정하지 않고 통과(최종적으로 401/403 날 것)
                } else {
                    String userid = tokenProvider.getUserid(token);
                    var opt = userRepository.findByUserid(userid);
                    if (opt.isPresent()) {
                        var role = opt.get().getRole().name();
                        var authentication = new UsernamePasswordAuthenticationToken(
                                userid, null, List.of(new SimpleGrantedAuthority(role)));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            }
        }
        chain.doFilter(req, res);
    }
}
