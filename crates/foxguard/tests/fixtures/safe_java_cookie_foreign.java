import org.openqa.selenium.Cookie;
import org.openqa.selenium.WebDriver;

// A different Cookie class: the servlet rule must not apply.
class BrowserCookies {
    void add(WebDriver driver) {
        Cookie c = new Cookie("a", "b");
        driver.manage().addCookie(c);
    }
}
