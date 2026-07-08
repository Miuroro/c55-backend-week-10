package net.hackyourfuture.security;

import com.auth0.jwt.JWT;
import org.springframework.beans.factory.annotation.Value;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.util.Date;

@Service
public class JwtService {

    private final Algorithm algorithm;

    public JwtService(@Value("${JWT_SECRET_KEY}") String secretKey) {
        this.algorithm = Algorithm.HMAC256(secretKey);
    }


     // Generating a new JWT token valid for 24 hours.
    public String generateToken(UserDetails userDetails) {
        return JWT.create()
                .withSubject(userDetails.getUsername())
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000))
                .sign(algorithm);
    }

    // Extracting the usernme from the token.
    public String extractUsername(String token) {
        DecodedJWT decodedJWT = JWT.require(algorithm)
                .build()
                .verify(token);
        return decodedJWT.getSubject();
    }


     // Validating if the token belongs to the user and isnt expired.
    public boolean isTokenValid(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        DecodedJWT decodedJWT = JWT.require(algorithm).build().verify(token);
        return decodedJWT.getExpiresAt().before(new Date());
    }
}