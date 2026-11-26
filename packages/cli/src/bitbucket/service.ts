/**
 * The pieces every Bitbucket review needs, built from plain settings: the API client, the scan runner and the review options.
 * `0security sentinels bitbucket review|watch` and the `bitbucket-pr` Sentinel trigger both build their reviewer here, so the two
 * cannot drift apart. The token comes from the caller; this file never reads the environment.
 */
import { resolve } from "node:path";
import { BitbucketClient, type Http, type Platform } from "./client.js";
import type { ReviewOptions, ReviewRunner } from "./review.js";
import { gitScanRunner, type Exec } from "./runner.js";

export type PlatformName = "cloud" | "dc";
export const PLATFORMS: Record<PlatformName, Platform> = { cloud: "bitbucket-cloud", dc: "bitbucket-dc" };

export interface ReviewerSettings {
  platform: PlatformName;
  /** `workspace/repo` (Cloud) or `PROJECT/repo` (Data Center). */
  repo: string;
  checkout: string;
  token: string;
  baseUrl?: string | undefined;
  allowInsecureHttp?: boolean;
  /** Spend limit for one scan, in USD, as the scan command takes it. */
  budget?: string;
  model?: string | undefined;
  maxFiles: number;
  maxInline: number;
  reportId: string;
  comments: boolean;
  insights: boolean;
  /** Environment variables the scan must not see, besides the default Bitbucket ones. */
  secretVariables?: string[];
}

export interface Reviewer {
  platform: Platform;
  owner: string;
  repo: string;
  client: BitbucketClient;
  runner: ReviewRunner;
  review: ReviewOptions;
}

/** `owner/repo` split in two, or undefined when it is not exactly two parts. */
export function splitRepo(value: string): { owner: string; repo: string } | undefined {
  const [owner, repo, extra] = value.split("/");
  return owner && repo && extra === undefined ? { owner, repo } : undefined;
}

export function createReviewer(settings: ReviewerSettings, seams: { http?: Http; exec?: Exec } = {}): Reviewer {
  const platform = PLATFORMS[settings.platform];
  const parts = splitRepo(settings.repo);
  if (!parts) throw new Error(`Name the repository as ${platform === "bitbucket-cloud" ? "workspace/repo" : "PROJECT/repo"}.`);
  const client = new BitbucketClient({
    platform, token: settings.token, ...(settings.baseUrl ? { baseUrl: settings.baseUrl } : {}),
    allowInsecureHttp: settings.allowInsecureHttp === true, ...(seams.http ? { http: seams.http } : {}),
  });
  const runner = gitScanRunner({
    checkout: resolve(settings.checkout), budget: settings.budget ?? "2", ...(settings.model ? { model: settings.model } : {}),
    ...(settings.secretVariables ? { secretVariables: settings.secretVariables } : {}), ...(seams.exec ? { exec: seams.exec } : {}),
  });
  return {
    platform, ...parts, client, runner,
    review: { reportId: settings.reportId, maxFiles: settings.maxFiles, maxInline: settings.maxInline, comments: settings.comments, insights: settings.insights },
  };
}
