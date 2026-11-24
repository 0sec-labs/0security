package app;

import java.io.Serializable;

public class Session implements Serializable {
    private static final long serialVersionUID = 1L;
    public final String user;
    public final boolean admin;

    public Session(String user, boolean admin) {
        this.user = user;
        this.admin = admin;
    }
}
