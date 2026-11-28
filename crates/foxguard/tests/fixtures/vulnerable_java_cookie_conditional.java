import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// Unsafe twins of safe_java_cookie.java: setSecure is called, but not on every
// path to addCookie, so the cookie can still go out without Secure.
// One finding per method.
class ConditionalCookies {
    void inIf(HttpServletResponse response, boolean flag) {
        Cookie c = new Cookie("session", "abc");
        if (flag) {
            c.setSecure(true);
        }
        response.addCookie(c);
    }

    void inElseBranchOnly(HttpServletResponse response, boolean flag) {
        Cookie c = new Cookie("session", "abc");
        if (flag) {
            response.addCookie(c);
        } else {
            c.setSecure(true);
            response.addCookie(c);
        }
    }

    void inLoop(HttpServletResponse response, java.util.List<String> xs) {
        Cookie c = new Cookie("session", "abc");
        for (String x : xs) {
            c.setSecure(true);
        }
        response.addCookie(c);
    }

    void inWhile(HttpServletResponse response, boolean more) {
        Cookie c = new Cookie("session", "abc");
        while (more) {
            c.setSecure(true);
            more = false;
        }
        response.addCookie(c);
    }

    void inSwitch(HttpServletResponse response, int mode) {
        Cookie c = new Cookie("session", "abc");
        switch (mode) {
            case 1:
                c.setSecure(true);
                break;
            default:
                break;
        }
        response.addCookie(c);
    }

    void inTernary(HttpServletResponse response, boolean flag) {
        Cookie c = new Cookie("session", "abc");
        Runnable r = flag ? () -> c.setSecure(true) : null;
        response.addCookie(c);
    }

    void inAnonymousClass(HttpServletResponse response) {
        Cookie c = new Cookie("session", "abc");
        Runnable r = new Runnable() {
            public void run() { c.setSecure(true); }
        };
        response.addCookie(c);
    }

    void inTry(HttpServletResponse response) {
        Cookie c = new Cookie("session", "abc");
        try {
            risky();
            c.setSecure(true);
        } catch (RuntimeException e) {
            // setSecure may never have run
        }
        response.addCookie(c);
    }

    void inCatch(HttpServletResponse response) {
        Cookie c = new Cookie("session", "abc");
        try {
            risky();
        } catch (RuntimeException e) {
            c.setSecure(true);
        }
        response.addCookie(c);
    }

    void inLambda(HttpServletResponse response) {
        Cookie c = new Cookie("session", "abc");
        Runnable r = () -> c.setSecure(true);
        response.addCookie(c);
    }

    void inShortCircuit(boolean flag, HttpServletResponse response) {
        Cookie c = new Cookie("session", "abc");
        boolean ok = flag && ((Runnable) () -> c.setSecure(true)) != null;
        response.addCookie(c);
    }

    void afterSink(HttpServletResponse response) {
        Cookie c = new Cookie("session", "abc");
        response.addCookie(c);
        c.setSecure(true);
    }

    void dynamicInIf(HttpServletRequest request, HttpServletResponse response, boolean flag) {
        Cookie c = new Cookie("session", "abc");
        if (flag) {
            c.setSecure(request.isSecure());
        }
        response.addCookie(c);
    }

    void oneSinkUncovered(HttpServletResponse response, boolean flag) {
        Cookie d = new Cookie("other", "abc");
        if (flag) {
            d.setSecure(true);
            response.addCookie(d);
        }
        response.addCookie(d);
    }

    void risky() {}
}
