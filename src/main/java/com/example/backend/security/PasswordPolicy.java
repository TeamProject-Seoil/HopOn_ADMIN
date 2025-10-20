// src/main/java/com.example.backend/security/PasswordPolicy.java
package com.example.backend.security;

import java.util.List;

public final class PasswordPolicy {
    private PasswordPolicy() {}

    /** 정책:
     *  - 길이 10~16
     *  - 영문 대문자/소문자/숫자 중 2종류 이상 혼합
     *  - 특수문자 불가(영문/숫자만)
     *  - 3자리 이상 연속된 알파벳/숫자열 금지 (예: abc, cde, 123, 987)
     *  - 3자리 이상 연속된 키보드 행 시퀀스 금지 (예: qwe, asd, zxc)
     */
    public static boolean validate(String pwd) {
        return validateAndReason(pwd) == null;
    }

    /** 정책 위반 사유 메시지(위반 없으면 null) */
    public static String validateAndReason(String pwd) {
        if (pwd == null) return "비밀번호가 비어 있습니다.";
        int len = pwd.length();
        if (len < 10 || len > 16) return "비밀번호는 10~16자로 입력하세요.";

        // 영문/숫자만
        if (!pwd.matches("^[A-Za-z0-9]+$")) return "비밀번호는 영문/숫자만 사용할 수 있습니다.";

        boolean hasUpper = pwd.chars().anyMatch(c -> c >= 'A' && c <= 'Z');
        boolean hasLower = pwd.chars().anyMatch(c -> c >= 'a' && c <= 'z');
        boolean hasDigit = pwd.chars().anyMatch(c -> c >= '0' && c <= '9');

        int classes = (hasUpper?1:0) + (hasLower?1:0) + (hasDigit?1:0);
        if (classes < 2) return "영문 대문자, 소문자, 숫자 중 2종류 이상을 섞어주세요.";

        // 3자리 연속 증가/감소 숫자/알파벳 금지
        if (hasSequentialAlphaOrDigit(pwd)) return "연속된 문자/숫자열(3자리 이상)은 사용할 수 없습니다.";

        // 키보드 행 시퀀스 금지(qwerty/asdf/zxc 등)
        if (hasKeyboardSequence(pwd)) return "키보드 상 연속된 문자열(3자리 이상)은 사용할 수 없습니다.";

        return null;
    }

    private static boolean hasSequentialAlphaOrDigit(String s) {
        for (int i = 0; i <= s.length() - 3; i++) {
            char a = s.charAt(i), b = s.charAt(i+1), c = s.charAt(i+2);
            // 모두 숫자
            if (Character.isDigit(a) && Character.isDigit(b) && Character.isDigit(c)) {
                int x=a, y=b, z=c;
                if ((y==x+1 && z==y+1) || (y==x-1 && z==y-1)) return true;
            }
            // 모두 알파벳(대소문자 구분 없이)
            if (Character.isLetter(a) && Character.isLetter(b) && Character.isLetter(c)) {
                int x=Character.toLowerCase(a), y=Character.toLowerCase(b), z=Character.toLowerCase(c);
                if ((y==x+1 && z==y+1) || (y==x-1 && z==y-1)) return true;
            }
        }
        return false;
    }

    private static boolean hasKeyboardSequence(String s) {
        String lower = s.toLowerCase();
        List<String> rows = List.of(
                "qwertyuiop",
                "asdfghjkl",
                "zxcvbnm",
                "1234567890",
                "0987654321"
        );
        for (String row : rows) {
            // 증가 방향
            for (int i=0; i<=row.length()-3; i++) {
                String sub = row.substring(i, i+3);
                if (lower.contains(sub)) return true;
            }
            // 감소 방향(역순)
            String rev = new StringBuilder(row).reverse().toString();
            for (int i=0; i<=rev.length()-3; i++) {
                String sub = rev.substring(i, i+3);
                if (lower.contains(sub)) return true;
            }
        }
        return false;
    }
}
