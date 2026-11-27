package com.lookahead.gateway.security.filter;

import com.lookahead.gateway.log.OpsLog;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Fixed event codes only: no request, identity, token, exception or payload fields.
 *
 * <p>Exception, decided 2026-11-25 (DLV-1015): this filter exists only to log (rule 6: no class may exist only to log).
 * After the chain it writes the audit line for a 401 or 403, on behalf of whichever filter, security rule or controller
 * produced the status. It runs in DEV only, at order -250; {@code RequestLog} runs in every mode as the outermost
 * filter, so moving the line there would change which requests get it and when.
 */
@Component @Profile("lower-cost-dev") @Order(-250)
public final class SecurityAuditFilter extends OncePerRequestFilter {
    @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain)throws IOException,ServletException {
        chain.doFilter(request,response);
        if(response.getStatus()==401)OpsLog.audit(OpsLog.AuditEvent.AUTHENTICATION_REJECTED);
        else if(response.getStatus()==403)OpsLog.audit(OpsLog.AuditEvent.AUTHORIZATION_REJECTED);
    }
}
