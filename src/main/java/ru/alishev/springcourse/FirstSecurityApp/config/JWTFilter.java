package ru.alishev.springcourse.FirstSecurityApp.config;

import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.alishev.springcourse.FirstSecurityApp.security.JWTUtil;
import ru.alishev.springcourse.FirstSecurityApp.services.PersonDetailsService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;
    private final PersonDetailsService personDetailsService;

    public JWTFilter(JWTUtil jwtUtil, PersonDetailsService personDetailsService) {
        this.jwtUtil = jwtUtil;
        this.personDetailsService = personDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = httpServletRequest.getHeader("Authorization");
        if (header != null && !header.isBlank() && header.startsWith("Bearer ")) {
            String jwt = header.substring(7);

            if (jwt.isBlank()) {
                httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid JWT Token in Bearer Header");
            } else {
                try {
                    String username = jwtUtil.validateTokenAndRetrieveClaim(jwt);
                    UserDetails userDetails = personDetailsService.loadUserByUsername(username);

                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());

                    if (SecurityContextHolder.getContext().getAuthentication() == null) {
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    }
                } catch (JWTVerificationException exception) {
                    httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid JWT Token");

                }
            }
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
