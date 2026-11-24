package bench.web;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AccountServlet extends HttpServlet {
    private final Connection db;

    public AccountServlet(Connection db) {
        this.db = db;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        try {
            Statement st = db.createStatement();
            ResultSet rs = st.executeQuery("SELECT id, email FROM accounts WHERE name = '" + name + "'");
            while (rs.next()) {
                resp.getWriter().println(rs.getString("email"));
            }
        } catch (Exception e) {
            resp.sendError(500);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String id = req.getParameter("id");
        try {
            PreparedStatement ps = db.prepareStatement("SELECT email FROM accounts WHERE id = ?");
            ps.setInt(1, Integer.parseInt(id));
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                resp.getWriter().println(rs.getString("email"));
            }
        } catch (Exception e) {
            resp.sendError(500);
        }
    }
}
