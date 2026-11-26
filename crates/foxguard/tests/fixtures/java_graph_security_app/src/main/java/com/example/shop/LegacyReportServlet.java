package com.example.shop;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.FileInputStream;

// Mapped in WEB-INF/web.xml, which also restricts /legacy/* to the auditor role.
public class LegacyReportServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws java.io.IOException {
        new FileInputStream(req.getParameter("report")).transferTo(res.getOutputStream());
    }
}
