// AuthUserResolver.java
package com.example.backend.support;

import com.example.backend.entity.Role;
import com.example.backend.entity.UserEntity;
import com.example.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
@RequiredArgsConstructor
public class AuthUserResolver {

    private final UserRepository userRepository;

    /** 인증 필요 + 현재 principal(String userid) 기준으로 UserEntity 로드 */
    public UserEntity requireUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED");
        }

        Object p = authentication.getPrincipal();
        if (!(p instanceof String username)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "UNSUPPORTED_PRINCIPAL");
        }
        if ("anonymousUser".equals(username)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "ANONYMOUS");
        }

        String userid = normalizeUserid(username);
        return userRepository.findByUserid(userid)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "USER_NOT_FOUND"));
    }

    /** 관리자만 허용이 필요한 경우 빠른 체크 */
    public UserEntity requireAdmin(Authentication authentication) {
        UserEntity user = requireUser(authentication);
        if (user.getRole() != Role.ROLE_ADMIN) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "FORBIDDEN");
        }
        return user;
    }

    private static String normalizeUserid(String raw) {
        return raw == null ? null : raw.trim().toLowerCase();
    }
}
