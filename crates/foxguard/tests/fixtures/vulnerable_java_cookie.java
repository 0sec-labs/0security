import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class Cookies {
    void neverSecure(HttpServletResponse response) {
        Cookie c = new Cookie("session", "abc");
        c.setHttpOnly(true);
        response.addCookie(c);                                  // 1
    }

    void explicitlyInsecure(HttpServletResponse response) {
        Cookie c = new Cookie("pref", "dark");
        c.setSecure(false);                                     // 2
        response.addCookie(c);
    }

    void inline(HttpServletResponse response) {
        response.addCookie(new Cookie("x", "y"));               // 3
    }

    void qualified(HttpServletResponse response) {
        javax.servlet.http.Cookie c = new javax.servlet.http.Cookie("a", "b");
        response.addCookie(c);                                  // 4
    }
}
