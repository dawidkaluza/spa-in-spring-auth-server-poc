package pl.dkaluza.server;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Strategy that sends response HTTP 200 OK with response body containing url where a user should be redirected.
 */
@Component
class RestfulRedirectStrategy implements RedirectStrategy {
    @Override
    public void sendRedirect(HttpServletRequest req, HttpServletResponse res, String url) throws IOException {
        res.resetBuffer();
        res.setStatus(HttpServletResponse.SC_OK);
        res.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        res.getWriter()
            .append("{\"redirectUrl\": \"")
            .append(url)
            .append("\"}");
        res.flushBuffer();
    }
}