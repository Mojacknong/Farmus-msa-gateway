package com.example.farmusgateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Value("${baseurl.user}")
    private String userUrl;

    @Bean
    public RouteLocator gatewayRoutes(RouteLocatorBuilder builder) {
        // application.yml 에 적용한 라우팅 대신에 필터를 적용해서 처리
        return builder.routes()
                .route(r -> r.path("/api/user/auth/logout")
                        .filters(f -> f.addRequestHeader("user", "first-request-header"))
                        .uri(userUrl))

                .route(r -> r.path("/api/user/auth/reissue-token")
                        .filters(f -> f.addRequestHeader("user", "second-request-header")
                                .addRequestHeader("Authorization","sd")
                        )
                        .uri(userUrl))
                .build();
    }
}