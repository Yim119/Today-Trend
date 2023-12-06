package com.todaytrend.apigatewayserver.config;


import com.todaytrend.apigatewayserver.config.jwt.TokenProvider1;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final TokenProvider1 tokenProvider;
//    private final static String HEADER_AUTHORIZATION = "Authorization";
//    private final static String TOKEN_PREFIX = "Bearer ";

//    private final JwtProperties jwtProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
//        // 요청 헤더의 Authorization 키의 값 조회
//        String authorizationHeader = request.getHeader(HEADER_AUTHORIZATION);
//        // 가져온 값에서 접두사 제거
//        String token = getAccessToken(authorizationHeader);
//        // 가져온 토큰이 유효한지 확인하고, 유효한 때는 인증 정보를 설정
//        if (tokenProvider.validToken(token)) {
//            Authentication authentication = tokenProvider.getAuthentication(token);
//            SecurityContextHolder.getContext().setAuthentication(authentication);
//        }

//        String path = exchange.getRequest().getPath().toString();
//        // 예외 경로인 경우 필터 적용 x
//        if (exceptionPathManager.isExceptionPath(path)) {
//            return chain.filter(exchange);
//        }
        String accessTokenCookie = "";

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                String cookieName = cookie.getName();
                String cookieValue = cookie.getValue();
                // 여기에서 쿠키를 사용하거나 원하는 작업 수행
                if ("access_token".equals(cookie.getName())){
                    accessTokenCookie = cookieValue;
                }

            }
        }

        // 요청에서 쿠키 추출
//        MultiValueMap<String, HttpCookie> cookies = exchange.getRequest().getCookies();

        // 쿠키에서 access_token 추출
//        HttpCookie accessTokenCookie = cookies.getFirst("access_token");
        
        // todo: 예외처리
        // access_token이 없거나 토큰이 유효하지 않다면 401 Unauthorized 응답을 반환
//        if (accessTokenCookie == null || !tokenProvider.validateToken(accessTokenCookie.getValue())) {
//            return unauthorizedResponse(exchange);
//        }

        // getRoleFromToken 메서드를 이용해 Role 추출 및 비교
//        String role = getRoleFromToken(accessTokenCookie);
//        List<String> allowedRoles = Arrays.asList("ADMIN", "USER"); // asList 불변성 유지, 추가 및 삭제 용이
        // todo: 예외처리
//        if (!allowedRoles.contains(role)) {
//            return unauthorizedResponse(exchange);
//        }

        filterChain.doFilter(request, response);
    }

    // 요청 헤더의 키가 Authorization인 필드의 값을 가져온 다음 토큰의 접두사 Bearer를 제외한 값을 추출
//    private String getAccessToken(String authorizationHeader) {
//        if (authorizationHeader != null && authorizationHeader.startsWith(TOKEN_PREFIX)) {
//            return authorizationHeader.substring(TOKEN_PREFIX.length());
//        }
//        return null;
//    }

    // 토큰에서 클레임 추출
//    public Claims extractAllClaims(String token) {
//        return Jwts.parser().setSigningKey(jwtProperties.getSecretKey()).parseClaimsJws(token).getBody();
//    }
//
//    public String getRoleFromToken(String token) {
//        try {
//            Claims claims = extractAllClaims(token); // 토큰에서 모든 Claim 추출
//            return claims.get("role", String.class); // Role 클레임 추출
//        } catch (JwtException | IllegalArgumentException e){
//            return "유효한 토큰이 아닙니다.";
//        }
//    }
}
