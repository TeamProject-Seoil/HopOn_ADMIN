// src/main/java/com/example/backend/events/DriverApprovalMailListener.java
package com.example.backend.events;

import com.example.backend.support.MailService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

@Component
@RequiredArgsConstructor
public class DriverApprovalMailListener {

    private final MailService mail;

    private static final ZoneId KST = ZoneId.of("Asia/Seoul");
    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onApproved(DriverApprovalEvent e) {
        if (!StringUtils.hasText(e.email()))
            return;

        String subject = "[HopOn] 드라이버 승인 완료: " + e.userid();
        String when = LocalDateTime.now(KST).format(TS_FMT);

        String html = """
                <p>%s님, 안녕하세요.</p>
                <p>요청하신 드라이버 등록이 <b style="color:#2bb673">승인</b>되었습니다.</p>
                <ul>
                  <li>아이디: <b>%s</b></li>
                  <li>승인일시: %s (KST)</li>
                </ul>
                <p>이제 드라이버 앱에서 로그인 후 운행을 시작할 수 있습니다.</p>
                <p style="color:#666;font-size:12px">※ 본 메일은 발신 전용입니다.</p>
                """.formatted(esc(e.username()), esc(e.userid()), esc(when));

        String text = """
                %s님, 안녕하세요.
                요청하신 드라이버 등록이 승인되었습니다.

                아이디: %s
                승인일시: %s (KST)

                이제 드라이버 앱에서 로그인 후 운행을 시작할 수 있습니다.
                """.formatted(e.username(), e.userid(), when);

        mail.sendHtml(e.email(), subject, html, text);
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onRejected(DriverRejectionEvent e) {
        if (!StringUtils.hasText(e.email()))
            return;

        String subject = "[HopOn] 드라이버 승인 거절 안내: " + e.userid();
        String when = LocalDateTime.now(KST).format(TS_FMT);
        String reason = StringUtils.hasText(e.reason()) ? e.reason().trim() : "요건 미충족";

        String html = """
                <p>%s님, 안녕하세요.</p>
                <p>드라이버 등록 요청이 <b style="color:#e74c3c">거절</b>되었습니다.</p>
                <ul>
                  <li>아이디: <b>%s</b></li>
                  <li>처리일시: %s (KST)</li>
                  <li>사유: %s</li>
                </ul>
                <p>필요 서류 또는 이미지(운전면허) 상태를 확인하시고 다시 신청해주세요.</p>
                <p style="color:#666;font-size:12px">※ 본 메일은 발신 전용입니다.</p>
                """.formatted(esc(e.username()), esc(e.userid()), esc(when), esc(reason));

        String text = """
                %s님, 안녕하세요.
                드라이버 등록 요청이 거절되었습니다.

                아이디: %s
                처리일시: %s (KST)
                사유: %s

                필요 서류 또는 이미지를 보완 후 다시 신청해주세요.
                """.formatted(e.username(), e.userid(), when, reason);

        mail.sendHtml(e.email(), subject, html, text);
    }

    private static String esc(String s) {
        return HtmlUtils.htmlEscape(s == null ? "" : s);
    }
}
