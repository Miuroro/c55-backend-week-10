package net.hackyourfuture.security.authentication;

import lombok.AllArgsConstructor;
import net.hackyourfuture.security.authentication.dto.LoginRequest;
import net.hackyourfuture.security.authentication.dto.LoginResponse;
import org.springframework.stereotype.Service;
import net.hackyourfuture.security.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

@Service
@AllArgsConstructor
public class AuthenticationService {
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public LoginResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        // get the authenticated details
        UserDetails user = (UserDetails) authentication.getPrincipal();

        // Generating a token using JwtService
        String token = jwtService.generateToken(user);

        return new LoginResponse(token);
    }

    public void logout() {
    }
}
