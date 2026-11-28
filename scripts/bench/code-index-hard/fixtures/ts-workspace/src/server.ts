import { createApp } from "./app";
import { seed } from "./seed";

if (process.env.NODE_ENV !== "production") seed();

const port = Number(process.env.PORT ?? 4100);
createApp().listen(port, () => {
  console.log(`workspace api listening on ${port}`);
});
