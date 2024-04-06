package pl.dkaluza.server;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
class ConsentPageController {
    private final RestfulRedirectStrategy restfulRedirectStrategy;

    public ConsentPageController(RestfulRedirectStrategy restfulRedirectStrategy) {
        this.restfulRedirectStrategy = restfulRedirectStrategy;
    }

    @GetMapping("/consent-page")
    void consentPage(HttpServletRequest req, HttpServletResponse res) throws IOException {
        // Response could be returned as a JSON here as well,
        // but for POC I preferred to reuse existing restful redirect strategy.
        var redirectUrl = "http://localhost:9090/consent?" + req.getQueryString();
        restfulRedirectStrategy.sendRedirect(req, res, redirectUrl);
    }
}
