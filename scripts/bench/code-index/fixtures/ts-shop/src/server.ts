import express from "express";
import { loadUser } from "./middleware/auth";
import { ordersRouter } from "./routes/orders";
import { adminRouter } from "./routes/admin";
import { refundsRouter } from "./routes/refunds";
import { teamsRouter } from "./routes/teams";
import { profileRouter } from "./routes/profile";

const app = express();
app.use(express.json());
app.use(loadUser);
app.use(ordersRouter);
app.use(adminRouter);
app.use(refundsRouter);
app.use(teamsRouter);
app.use(profileRouter);
app.listen(3000);
