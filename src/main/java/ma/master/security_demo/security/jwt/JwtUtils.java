package ma.master.security_demo.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${app.jwtSecret:mySecretKey}")
    private String jwtSecret;

    @Value("${app.jwtExpirationMs:86400000}") // 24 hours
    private int jwtExpirationMs;

    /**
     * Generate JWT token from Authentication object
     */
    public String generateJwtToken(Authentication authentication) {
        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();
        return generateTokenFromUsername(userPrincipal.getUsername(), userPrincipal.getAuthorities());
    }

    /**
     * Generate JWT token from username and authorities
     */
    public String generateTokenFromUsername(String username, Collection<? extends GrantedAuthority> authorities) {
        try {
            List<String> roles = authorities != null ?
                    authorities.stream()
                            .map(GrantedAuthority::getAuthority)
                            .filter(Objects::nonNull)
                            .collect(Collectors.toList()) :
                    new ArrayList<>();

            return JWT.create()
                    .withSubject(username)
                    .withArrayClaim("roles", roles.toArray(new String[0]))
                    .withIssuedAt(new Date())
                    .withExpiresAt(new Date(System.currentTimeMillis() + jwtExpirationMs))
                    .sign(Algorithm.HMAC256(jwtSecret));

        } catch (JWTCreationException e) {
            logger.error("Error creating JWT token: {}", e.getMessage());
            throw new RuntimeException("Error creating JWT token", e);
        }
    }


    /**
     * Extract username from JWT token
     */
    public String getUserNameFromJwtToken(String token) {
        try {
            DecodedJWT decodedJWT = getDecodedJWT(token);
            return decodedJWT.getSubject();
        } catch (JWTVerificationException e) {
            logger.error("Error extracting username from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extract roles from JWT token
     */
    public List<String> getRolesFromToken(String token) {
        try {
            DecodedJWT decodedJWT = getDecodedJWT(token);
            String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
            return roles != null ? Arrays.asList(roles) : new ArrayList<>();
        } catch (JWTVerificationException e) {
            logger.error("Error extracting roles from token: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Check if token is expired
     */
    public boolean isTokenExpired(String token) {
        try {
            DecodedJWT decodedJWT = getDecodedJWT(token);
            return decodedJWT.getExpiresAt().before(new Date());
        } catch (JWTVerificationException e) {
            return true; // Consider invalid tokens as expired
        }
    }

    /**
     * Validate JWT token
     */
    public boolean validateJwtToken(String authToken) {
        try {
            getDecodedJWT(authToken);
            return true;
        } catch (JWTVerificationException e) {
            logger.error("JWT validation error: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Validate JWT token against UserDetails
     */
    public boolean validateJwtToken(String token, UserDetails userDetails) {
        final String username = getUserNameFromJwtToken(token);
        return (username != null &&
                username.equals(userDetails.getUsername()) &&
                !isTokenExpired(token));
    }

    /**
     * Extract token from Authorization header
     */
    public String extractTokenFromHeader(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }

    /**
     * Private helper method to decode and verify JWT
     */
    private DecodedJWT getDecodedJWT(String token) throws JWTVerificationException {
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(jwtSecret))
                .build();
        return verifier.verify(token);
    }
}