// src/main/java/com/example/backend/events/DriverApprovalEvent.java
package com.example.backend.events;

public record DriverApprovalEvent(
        Long userNum, String userid, String username, String email) {
}