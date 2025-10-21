// src/main/java/com/example/backend/events/DriverRejectionEvent.java
package com.example.backend.events;

public record DriverRejectionEvent(
        Long userNum, String userid, String username, String email, String reason) {
}
