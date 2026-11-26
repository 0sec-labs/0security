const express = require("express");
const { loadUser } = require("./middleware/auth");

const app = express();
app.use(express.json());
app.use(loadUser);
app.use(require("./routes/docs"));
app.use(require("./routes/collab"));
app.use(require("./routes/public"));
app.listen(3000);
