package com.todaytrend.apigatewayserver.config.jwt;

import com.todaytrend.apigatewayserver.jwt.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@RequiredArgsConstructor
@Service
public class TokenProvider1 {

    private final JwtProperties jwtProperties;
//    private final LocalUserRepository localUserRepository;

//    // 무효화된 토큰을 저장하는 리스트
//    private List<String> invalidatedTokens = new ArrayList<>();
//
//    public TokenInfo generateToken(UserInterface userInterface, Duration expiredAt, String tokenName) {
//        Date now = new Date();
//        String token = makeToken(new Date(now.getTime() + expiredAt.toMillis()), userInterface);
//
//        return new TokenInfo(token, (int) expiredAt.getSeconds());
//    }
//
//    // JWT 토큰 생성 메서드
//    private String makeToken(Date expiry, UserInterface userInterface){
//        Date now = new Date();
//
//        return Jwts.builder()
//                .setHeaderParam(Header.TYPE, Header.JWT_TYPE) // 헤더 typ :JWT
//                .setIssuer(jwtProperties.getIssuer()) // yml에 저장한 issuer 값
//                .setIssuedAt(now) // iat : 현재 시간
//                .setExpiration(expiry) // expiry 멤버 변숫값
//                .setSubject(userInterface.getUuid()) // uuid로 생성
//                .claim("uuid", userInterface.getUuid()) // 유저 uuid
//                .claim("role", userInterface.getRole()) // 유저 Role
//                // 서명 : 비밀값과 함께 해시값을 HS256 방식으로 암호화
//                .signWith(SignatureAlgorithm.HS256, jwtProperties.getSecretKey())
//                .compact();
//    }

    // JWT 토큰 유효성 검증 메서드
    public boolean validToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(jwtProperties.getSecretKey()) // 비밀값으로 복호화
                    .parseClaimsJws(token);
//            // 토큰이 무효화된 토큰 리스트에 있으면 유효하지 않음
//            if (invalidatedTokens.contains(token)) {
//                return false;
//            }
            return true;
        } catch (Exception e) { // 복호화 과정에서 에러가 나면 유효하지 않은 토큰
            return false;
        }
    }

    // 토큰 기반으로 인증 정보를 가져오는 메서드
    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);
//        LocalUser localUser = findLocalUserByUuid(claims.getSubject());

        return new UsernamePasswordAuthenticationToken(
                new UserDetails() {
                    @Override
                    public Collection<? extends GrantedAuthority> getAuthorities() {
                        return List.of(new SimpleGrantedAuthority("USER"));
                    }

                    @Override
                    public String getPassword() {
                        return null;
                    }

                    @Override
                    public String getUsername() {
                        return null;
                    }

                    @Override
                    public boolean isAccountNonExpired() {
                        return false;
                    }

                    @Override
                    public boolean isAccountNonLocked() {
                        return false;
                    }

                    @Override
                    public boolean isCredentialsNonExpired() {
                        return false;
                    }

                    @Override
                    public boolean isEnabled() {
                        return false;
                    }
                }, token, List.of(new SimpleGrantedAuthority("USER")));
        // todo: 사용
//        return new UsernamePasswordAuthenticationToken(
//                localUser, token, localUser.getAuthorities());
    }
//
//    // 토큰을 기반으로 UUID를 가져오는 메서드
//    public String getUserUuid(String token){
//        Claims claims = Jwts.parser().setSigningKey(jwtProperties.getSecretKey()).parseClaimsJws(token).getBody();
//        return claims.getSubject();
//    }
//
//    private LocalUser findLocalUserByEmail(String email) {
//        return localUserRepository.findByEmail(email)
//                .orElseThrow(() -> new UsernameNotFoundException("존재하지 않는 이메일 입니다. : " + email));
//    }
//
//    // LocalUser
//    private LocalUser findLocalUserByUuid(String uuid) {
//        return localUserRepository.findByUuid(uuid)
//                .orElseThrow(() -> new UsernameNotFoundException("존재하지 않는 UUID 입니다. : " + uuid ));
//    }

//    // 토큰 기반으로 유저 ID를 가져오는 메서드
//    public Long getLocalUserId(String token) {
//        Claims claims = getClaims(token);
//        System.out.println("claims = " + claims.get("localUserId", Long.class));
//        return claims.get("localUserId", Long.class);
//    }

    // 토큰 기반으로 유저 UUID를 가져오는 메서드
    public String getLocalUserUuid(String token) {
        Claims claims = getClaims(token);
        System.out.println("claims = " + claims.getSubject());
        return claims.getSubject();
    }

    private Claims getClaims(String token) {
        return Jwts.parser() // 클레임 조회
                .setSigningKey(jwtProperties.getSecretKey())
                .parseClaimsJws(token)
                .getBody();
    }

//    // JWT 토큰 무효화
//    public void invalidateJwt(String token) {
//        invalidatedTokens.add(token);
//    }
}
