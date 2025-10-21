// src/main/java/com/example/backend/support/MailService.java
package com.example.backend.support;

import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.Nullable;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromAddress;

    @Value("${app.mail.from-name:HopOn Admin}")
    private String fromName;

    public void sendHtml(String to, String subject, String htmlBody, @Nullable String plainTextFallback) {
        try {
            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, "UTF-8");
            helper.setFrom(new InternetAddress(fromAddress, fromName, "UTF-8"));
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(plainTextFallback == null ? " " : plainTextFallback, htmlBody);
            mailSender.send(msg);
        } catch (Exception e) {
            // 운영에서는 로깅 시스템으로 보내기
            e.printStackTrace();
        }
    }
}
