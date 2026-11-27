import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class SafeCookies {
    void secure(HttpServletResponse response) {
        Cookie c = new Cookie("session", "abc");
        c.setSecure(true);
        response.addCookie(c);
    }

    // The flag follows the transport the request arrived on.
    void dynamic(HttpServletRequest request, HttpServletResponse response) {
        Cookie c = new Cookie("session", "abc");
        c.setSecure(request.isSecure());
        response.addCookie(c);
    }

    // A helper owns the flag; the cookie leaves this method.
    void delegated(HttpServletResponse response) {
        Cookie c = new Cookie("session", "abc");
        CookieDefaults.harden(c);
        response.addCookie(c);
    }

    Cookie factory() {
        Cookie c = new Cookie("session", "abc");
        return c;
    }

    // Created but never sent.
    void unused() {
        Cookie c = new Cookie("n", "v");
        c.setMaxAge(0);
    }

    // Clearing a cookie: expired or emptied, no credential is sent.
    void clear(HttpServletResponse response) {
        Cookie gone = new Cookie("session", "x");
        gone.setMaxAge(0);
        response.addCookie(gone);
        response.addCookie(new Cookie("token", ""));
    }
}
