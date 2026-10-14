package com.lookahead.learning.content.gateway;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.time.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;
final class LearnerIdleFilter extends OncePerRequestFilter {
    static final String LAST_ACTIVITY="lookaheadLearnerActivity";
    private final Clock clock;
    LearnerIdleFilter(Clock clock){this.clock=clock;}
    @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain)throws IOException,ServletException{
        var session=request.getSession(false);
        if(session!=null && SecurityContextHolder.getContext().getAuthentication() instanceof OAuth2AuthenticationToken){
            Instant now=clock.instant();Object last=session.getAttribute(LAST_ACTIVITY);
            if(!(last instanceof Instant instant)||!now.isBefore(instant.plusSeconds(1800))) DevAdmission.clearLearner(request);
            else if(activity(request)) session.setAttribute(LAST_ACTIVITY,now);
        }
        chain.doFilter(request,response);
    }
    static boolean activity(HttpServletRequest r){
        String path=r.getRequestURI();
        if(path.equals("/bff/api/v1/auth/me")||path.endsWith("/csrf")||path.startsWith("/dev/")||path.startsWith("/actuator/"))return false;
        return !r.getMethod().equals("GET") && !r.getMethod().equals("HEAD") || path.startsWith("/content/")
            || DevWebProxy.safePath(path)&&!path.contains(".");
    }
}
