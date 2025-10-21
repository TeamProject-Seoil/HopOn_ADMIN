// src/main/java/com/example/backend/entity/InquiryStatus.java
package com.example.backend.entity;

public enum InquiryStatus {
    OPEN,       // 접수됨(미답변)
    ANSWERED,   // 답변 완료(최신 답변 존재)
    CLOSED      // 처리 종료
}
