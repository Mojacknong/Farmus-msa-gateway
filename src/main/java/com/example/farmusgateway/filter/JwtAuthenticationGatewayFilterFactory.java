package com.example.farmusgateway.filter;


import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class JwtAuthenticationGatewayFilterFactory extends AbstractGatewayFilterFactory<JwtAuthenticationGatewayFilterFactory.Config> {

    @Value("${jwt.secret}")
    private String secret;

    public JwtAuthenticationGatewayFilterFactory() {
        super(Config.class);

    }

    // login -> token -> users (with token) -> header(include token)
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            log.info("authorizationHeader : {}", authorizationHeader);
            String jwt = authorizationHeader.replace("Bearer ", "");
            log.info("jwt : {}", jwt);

            String subject = decode(jwt);
            request.mutate()
                    .header("user", subject)
                    .build();

            log.info("request.getURI().toString() : {}", request.getURI().toString());

            // get url after endpoint
            int index = request.getURI().toString().indexOf("/api");
            String url = request.getURI().toString().substring(index);

            log.info("url : {}", url);

            if(url.equals("/api/user/reissue-token")) {
                return chain.filter(exchange);
            }

            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "no authorization header", HttpStatus.UNAUTHORIZED);
            }

            if(!isJwtValid(jwt, exchange)) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            // 헤더 출력
            request.getHeaders().forEach((k, v) -> {
                log.info("{} : {}", k, v);
            });

            // Custom Post Filter
            return chain.filter(exchange);
        };
    }

    private boolean isJwtValid(String jwt, ServerWebExchange exchange) {
        boolean returnValue = true;

        try {
            String subject = Jwts.parserBuilder().setSigningKey(secret).build()
                    .parseClaimsJws(jwt).getBody()
                    .getSubject();

            log.info("subject : {}", subject);

            if (subject == null || subject.isEmpty()) {
                returnValue = false;
                onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }
        } catch (IllegalArgumentException e) {
            returnValue = false;
            onError(exchange, "Invalid access token header", HttpStatus.BAD_REQUEST);
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            returnValue = false;
            onError(exchange, "Verification error", HttpStatus.UNAUTHORIZED);
        } catch (ExpiredJwtException e) {
            returnValue = false;
            onError(exchange, "Token expired", HttpStatus.PRECONDITION_FAILED);
        } catch (JwtException e) {
            returnValue = false;
            onError(exchange, "JWT error", HttpStatus.UNAUTHORIZED);
        }

        return returnValue;
    }

    public String decode(String token) {

        String subject = null;
        try {
            subject = Jwts.parser().setSigningKey(secret)
                    .parseClaimsJws(token).getBody()
                    .getSubject();
        } catch(Exception ex) {
            onError(null, "JWT error", HttpStatus.UNAUTHORIZED);
        }

        if(subject == null || subject.isEmpty()) {
            onError(null, "JWT error", HttpStatus.UNAUTHORIZED);
        }

        return subject;
    }

    // Mono, Flux -> Spring WebFlux
    private Mono<Void> onError(ServerWebExchange exchange, String error, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(error);

        return response.setComplete();
    }

    @Data
    public static class Config {

    }
}
