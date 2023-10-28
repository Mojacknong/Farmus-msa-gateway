package com.example.farmusgateway.filter;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
@Slf4j
public class JwtAuthenticationGatewayFilterFactory extends AbstractGatewayFilterFactory<JwtAuthenticationGatewayFilterFactory.Config> {

    @Value("${jwt.secret}")
    private String secret;

    public JwtAuthenticationGatewayFilterFactory() {
        super(Config.class);

    }


    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            log.info("authorizationHeader: {}", authorizationHeader);
            String jwt = authorizationHeader.replace("Bearer ", "");
            log.info("jwt: {}", jwt);

            try {
                String subject = Jwts.parserBuilder().setSigningKey(secret).build()
                        .parseClaimsJws(jwt).getBody()
                        .getSubject();

                if (subject == null || subject.isEmpty()) {
                    return onError(response, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
                }

                String decodedSubject = decode(jwt);
                request.mutate().header("user", decodedSubject).build();

                // get url after endpoint
                int index = request.getURI().toString().indexOf("/api");
                String url = request.getURI().toString().substring(index);
                log.info("url: {}", url);

                if (url.equals("/api/user/reissue-token")) {
                    return chain.filter(exchange);
                }

                return chain.filter(exchange);
            } catch (IllegalArgumentException e) {
                return onError(response, "Invalid access token header", HttpStatus.BAD_REQUEST);
            } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
                return onError(response, "Verification error", HttpStatus.UNAUTHORIZED);
            } catch (ExpiredJwtException e) {
                return onError(response, "Token expired", HttpStatus.PRECONDITION_FAILED);
            } catch (JwtException e) {
                return onError(response, "JWT error", HttpStatus.UNAUTHORIZED);
            }
        };
    }


    public String decode(String token) {

        String subject = null;

        subject = Jwts.parser().setSigningKey(secret)
                .parseClaimsJws(token).getBody()
                .getSubject();

        return subject;
    }

    private Mono<Void> onError(ServerHttpResponse response, String message, HttpStatus status) {

        int statusCode = status.value(); // 상태 코드 가져오기
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // JSON 포맷으로 응답 데이터 구성
        String jsonResponse = "{\"message\": \"" + message + "\", \"code\":" + statusCode + "}";

        DataBuffer buffer = response.bufferFactory().wrap(jsonResponse.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    @Data
    public static class Config {

    }
}
