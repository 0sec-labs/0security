const { Worker } = require("bullmq");
const mailer = require("../services/mailer");

const worker = new Worker("email", async job => {
  await mailer.send(job.data.to, job.data.subject, job.data.text);
}, { connection: { host: process.env.REDIS_HOST || "127.0.0.1" } });

worker.on("failed", (job, err) => console.error(`email job ${job?.id} failed: ${err.message}`));
