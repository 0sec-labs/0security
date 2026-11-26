import { createApp } from "./app";
import { config } from "./lib/config";

createApp().listen(config.port, () => {
  console.log("tenantly api listening on " + config.port);
});
