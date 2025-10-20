package com.example.backend.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    @Value("${publicdata.serviceKey}")
    private String serviceKey;

    @Bean
    WebClient publicDataWebClient(WebClient.Builder builder) {
        return builder
            .baseUrl("http://ws.bus.go.kr/api/rest")
            .build();
    }
}
