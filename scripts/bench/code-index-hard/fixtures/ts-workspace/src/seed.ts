import { hashPasscode } from "./lib/passcode";
import { orgRepo } from "./repositories/orgRepo";
import { userRepo } from "./repositories/userRepo";
import { projectRepo } from "./repositories/projectRepo";
import { taskRepo } from "./repositories/taskRepo";
import { commentRepo } from "./repositories/commentRepo";
import { invoiceRepo } from "./repositories/invoiceRepo";
import { webhookRepo } from "./repositories/webhookRepo";
import { activityRepo } from "./repositories/activityRepo";
import { boardRepo } from "./repositories/boardRepo";
import { timeEntryRepo } from "./repositories/timeEntryRepo";
import { labelRepo } from "./repositories/labelRepo";
import { milestoneRepo } from "./repositories/milestoneRepo";
import { noteRepo } from "./repositories/noteRepo";
import { sprintRepo } from "./repositories/sprintRepo";
import { epicRepo } from "./repositories/epicRepo";
import { reminderRepo } from "./repositories/reminderRepo";
import { tagRepo } from "./repositories/tagRepo";
import { templateRepo } from "./repositories/templateRepo";
import { automationRepo } from "./repositories/automationRepo";
import { integrationLinkRepo } from "./repositories/integrationLinkRepo";
import { apiKeyRepo } from "./repositories/apiKeyRepo";
import { notificationRepo } from "./repositories/notificationRepo";
import { dashboardRepo } from "./repositories/dashboardRepo";
import { goalRepo } from "./repositories/goalRepo";
import { timesheetRepo } from "./repositories/timesheetRepo";
import { releaseRepo } from "./repositories/releaseRepo";
import { componentRepo } from "./repositories/componentRepo";
import { approvalRepo } from "./repositories/approvalRepo";
import { pollRepo } from "./repositories/pollRepo";
import { checklistRepo } from "./repositories/checklistRepo";
import { customFieldRepo } from "./repositories/customFieldRepo";

let seeded = false;

export function seed() {
  if (seeded) return;
  seeded = true;
  const at = "2026-01-05T09:00:00.000Z";

  orgRepo.insert({ id: "org_acme", name: "Acme Robotics", plan: "business", seats: 25, renewsAt: "2026-09-01", paymentMethodLast4: "4242" });
  orgRepo.insert({ id: "org_globex", name: "Globex Logistics", plan: "team", seats: 8, renewsAt: "2026-06-15", paymentMethodLast4: "1881" });
  orgRepo.insert({ id: "org_platform", name: "Platform", plan: "business", seats: 5, renewsAt: "2030-01-01", paymentMethodLast4: "0000" });

  userRepo.insert({ id: "usr_alice", orgId: "org_acme", name: "Alice Archer", email: "alice@acme.test", role: "manager", passcode: hashPasscode("pw-alice") });
  userRepo.insert({ id: "usr_bob", orgId: "org_acme", name: "Bob Baker", email: "bob@acme.test", role: "member", passcode: hashPasscode("pw-bob") });
  userRepo.insert({ id: "usr_carol", orgId: "org_globex", name: "Carol Cho", email: "carol@globex.test", role: "manager", passcode: hashPasscode("pw-carol") });
  userRepo.insert({ id: "usr_dave", orgId: "org_globex", name: "Dave Diaz", email: "dave@globex.test", role: "member", passcode: hashPasscode("pw-dave") });
  userRepo.insert({ id: "usr_root", orgId: "org_platform", name: "Root Operator", email: "root@platform.test", role: "admin", passcode: hashPasscode("pw-root") });

  projectRepo.insert({ id: "prj_acme", orgId: "org_acme", ownerId: "usr_alice", name: "Acme Roadmap", archived: false });
  projectRepo.insert({ id: "prj_globex", orgId: "org_globex", ownerId: "usr_carol", name: "Globex Fleet", archived: false });

  taskRepo.insert({ id: "tsk_a1", orgId: "org_acme", projectId: "prj_acme", ownerId: "usr_alice", title: "Launch checklist", notes: "public launch items", visibility: "public", watchers: ["usr_alice"], status: "open" });
  taskRepo.insert({ id: "tsk_a2", orgId: "org_acme", projectId: "prj_acme", ownerId: "usr_alice", title: "Acquisition talks", notes: "confidential: term sheet draft", visibility: "private", watchers: ["usr_alice"], status: "open" });
  taskRepo.insert({ id: "tsk_a3", orgId: "org_acme", projectId: "prj_acme", ownerId: "usr_bob", parentId: "tsk_a1", title: "Draft launch post", notes: "", visibility: "public", watchers: ["usr_bob"], status: "open" });
  taskRepo.insert({ id: "tsk_g1", orgId: "org_globex", projectId: "prj_globex", ownerId: "usr_carol", title: "Renew depot lease", notes: "ours", visibility: "private", watchers: ["usr_carol"], status: "open" });
  taskRepo.insert({ id: "tsk_g2", orgId: "org_globex", projectId: "prj_globex", ownerId: "usr_dave", title: "Route audit", notes: "ours", visibility: "private", watchers: ["usr_dave"], status: "open" });

  activityRepo.insert({ id: "act_a1", orgId: "org_acme", entity: "task", entityId: "tsk_a2", actorId: "usr_alice", action: "updated", detail: "notes: term sheet v3 from Initech Capital", at });
  activityRepo.insert({ id: "act_g1", orgId: "org_globex", entity: "task", entityId: "tsk_g1", actorId: "usr_carol", action: "created", detail: "Renew depot lease", at });

  commentRepo.insert({ id: "cmt_a1", orgId: "org_acme", taskId: "tsk_a2", authorId: "usr_alice", body: "wire details for the escrow account are in the shared vault", createdAt: at });
  commentRepo.insert({ id: "cmt_g1", orgId: "org_globex", taskId: "tsk_g1", authorId: "usr_carol", body: "landlord wants a counter by Friday", createdAt: at });

  timeEntryRepo.insert({ id: "tim_a1", orgId: "org_acme", taskId: "tsk_a1", userId: "usr_alice", minutes: 45, note: "kickoff" });

  invoiceRepo.insert({ id: "inv_a1", orgId: "org_acme", number: "ACM-0042", customer: "Initech Ltd", amountCents: 1250000, status: "sent", lines: [{ description: "Pilot fleet licence", amountCents: 1250000 }], internalNote: "margin 38 percent, do not share" });
  invoiceRepo.insert({ id: "inv_g1", orgId: "org_globex", number: "GLX-0007", customer: "Hooli Retail", amountCents: 420000, status: "draft", lines: [{ description: "Route planning", amountCents: 420000 }], internalNote: "ours" });

  webhookRepo.insert({ id: "whk_a1", orgId: "org_acme", url: "https://hooks.acme.test/ingest", authToken: "acme-hook-token-9f3a", events: ["task.created"], active: true });
  webhookRepo.insert({ id: "whk_g1", orgId: "org_globex", url: "https://hooks.globex.test/ingest", authToken: "globex-hook-token-77c1", events: ["task.created"], active: true });
  webhookRepo.addDelivery({ id: "dlv_a1", webhookId: "whk_a1", event: "task.created", requestHeaders: { Authorization: "Bearer acme-hook-token-9f3a", "Content-Type": "application/json" }, requestBody: "{\"taskId\":\"tsk_a2\"}", responseStatus: 200 });
  webhookRepo.addDelivery({ id: "dlv_g1", webhookId: "whk_g1", event: "task.created", requestHeaders: { Authorization: "Bearer globex-hook-token-77c1", "Content-Type": "application/json" }, requestBody: "{\"taskId\":\"tsk_g1\"}", responseStatus: 200 });

  boardRepo.insert({ id: "brd_a1", orgId: "org_acme", projectId: "prj_acme", slug: "acme-roadmap", published: true });
  boardRepo.insert({ id: "brd_g1", orgId: "org_globex", projectId: "prj_globex", slug: "globex-fleet", published: false });
  labelRepo.insert({ id: "label_a1", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", color: "sample color", createdAt: at });
  labelRepo.insert({ id: "label_a2", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", color: "sample color", createdAt: at });
  labelRepo.insert({ id: "label_g1", orgId: "org_globex", ownerId: "usr_carol", name: "sample name", color: "sample color", createdAt: at });
  milestoneRepo.insert({ id: "milestone_a1", orgId: "org_acme", ownerId: "usr_alice", title: "sample title", dueOn: "sample dueOn", archived: false, createdAt: at });
  milestoneRepo.insert({ id: "milestone_a2", orgId: "org_acme", ownerId: "usr_alice", title: "sample title", dueOn: "sample dueOn", archived: false, createdAt: at });
  milestoneRepo.insert({ id: "milestone_g1", orgId: "org_globex", ownerId: "usr_carol", title: "sample title", dueOn: "sample dueOn", archived: false, createdAt: at });
  noteRepo.insert({ id: "note_a1", orgId: "org_acme", ownerId: "usr_alice", title: "sample title", body: "sample body", archived: false, createdAt: at });
  noteRepo.insert({ id: "note_a2", orgId: "org_acme", ownerId: "usr_alice", title: "sample title", body: "sample body", archived: false, createdAt: at });
  noteRepo.insert({ id: "note_g1", orgId: "org_globex", ownerId: "usr_carol", title: "sample title", body: "sample body", archived: false, createdAt: at });
  sprintRepo.insert({ id: "sprint_a1", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", goal: "sample goal", capacity: 3, createdAt: at });
  sprintRepo.insert({ id: "sprint_a2", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", goal: "sample goal", capacity: 3, createdAt: at });
  sprintRepo.insert({ id: "sprint_g1", orgId: "org_globex", ownerId: "usr_carol", name: "sample name", goal: "sample goal", capacity: 3, createdAt: at });
  epicRepo.insert({ id: "epic_a1", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", summary: "sample summary", createdAt: at });
  epicRepo.insert({ id: "epic_a2", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", summary: "sample summary", createdAt: at });
  epicRepo.insert({ id: "epic_g1", orgId: "org_globex", ownerId: "usr_carol", name: "sample name", summary: "sample summary", createdAt: at });
  reminderRepo.insert({ id: "reminder_a1", orgId: "org_acme", ownerId: "usr_alice", message: "sample message", remindAt: "sample remindAt", createdAt: at });
  reminderRepo.insert({ id: "reminder_a2", orgId: "org_acme", ownerId: "usr_alice", message: "sample message", remindAt: "sample remindAt", createdAt: at });
  reminderRepo.insert({ id: "reminder_g1", orgId: "org_globex", ownerId: "usr_carol", message: "sample message", remindAt: "sample remindAt", createdAt: at });
  tagRepo.insert({ id: "tag_a1", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", archived: false, createdAt: at });
  tagRepo.insert({ id: "tag_a2", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", archived: false, createdAt: at });
  tagRepo.insert({ id: "tag_g1", orgId: "org_globex", ownerId: "usr_carol", name: "sample name", archived: false, createdAt: at });
  templateRepo.insert({ id: "template_a1", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", body: "sample body", archived: false, createdAt: at });
  templateRepo.insert({ id: "template_a2", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", body: "sample body", archived: false, createdAt: at });
  templateRepo.insert({ id: "template_g1", orgId: "org_globex", ownerId: "usr_carol", name: "sample name", body: "sample body", archived: false, createdAt: at });
  automationRepo.insert({ id: "automation_a1", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", trigger: "sample trigger", enabled: true, createdAt: at });
  automationRepo.insert({ id: "automation_a2", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", trigger: "sample trigger", enabled: true, createdAt: at });
  automationRepo.insert({ id: "automation_g1", orgId: "org_globex", ownerId: "usr_carol", name: "sample name", trigger: "sample trigger", enabled: true, createdAt: at });
  integrationLinkRepo.insert({ id: "integration-link_a1", orgId: "org_acme", ownerId: "usr_alice", provider: "sample provider", externalId: "sample externalId", createdAt: at });
  integrationLinkRepo.insert({ id: "integration-link_a2", orgId: "org_acme", ownerId: "usr_alice", provider: "sample provider", externalId: "sample externalId", createdAt: at });
  integrationLinkRepo.insert({ id: "integration-link_g1", orgId: "org_globex", ownerId: "usr_carol", provider: "sample provider", externalId: "sample externalId", createdAt: at });
  apiKeyRepo.insert({ id: "api-key_a1", orgId: "org_acme", ownerId: "usr_alice", label: "sample label", scope: "sample scope", createdAt: at });
  apiKeyRepo.insert({ id: "api-key_a2", orgId: "org_acme", ownerId: "usr_alice", label: "sample label", scope: "sample scope", createdAt: at });
  apiKeyRepo.insert({ id: "api-key_g1", orgId: "org_globex", ownerId: "usr_carol", label: "sample label", scope: "sample scope", createdAt: at });
  notificationRepo.insert({ id: "notification_a1", orgId: "org_acme", ownerId: "usr_alice", title: "sample title", channel: "sample channel", archived: false, createdAt: at });
  notificationRepo.insert({ id: "notification_a2", orgId: "org_acme", ownerId: "usr_alice", title: "sample title", channel: "sample channel", archived: false, createdAt: at });
  notificationRepo.insert({ id: "notification_g1", orgId: "org_globex", ownerId: "usr_carol", title: "sample title", channel: "sample channel", archived: false, createdAt: at });
  dashboardRepo.insert({ id: "dashboard_a1", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", layout: "sample layout", createdAt: at });
  dashboardRepo.insert({ id: "dashboard_a2", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", layout: "sample layout", createdAt: at });
  dashboardRepo.insert({ id: "dashboard_g1", orgId: "org_globex", ownerId: "usr_carol", name: "sample name", layout: "sample layout", createdAt: at });
  goalRepo.insert({ id: "goal_a1", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", target: 3, archived: false, createdAt: at });
  goalRepo.insert({ id: "goal_a2", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", target: 3, archived: false, createdAt: at });
  goalRepo.insert({ id: "goal_g1", orgId: "org_globex", ownerId: "usr_carol", name: "sample name", target: 3, archived: false, createdAt: at });
  timesheetRepo.insert({ id: "timesheet_a1", orgId: "org_acme", ownerId: "usr_alice", weekOf: "sample weekOf", hours: 3, createdAt: at });
  timesheetRepo.insert({ id: "timesheet_a2", orgId: "org_acme", ownerId: "usr_alice", weekOf: "sample weekOf", hours: 3, createdAt: at });
  timesheetRepo.insert({ id: "timesheet_g1", orgId: "org_globex", ownerId: "usr_carol", weekOf: "sample weekOf", hours: 3, createdAt: at });
  releaseRepo.insert({ id: "release_a1", orgId: "org_acme", ownerId: "usr_alice", version: "sample version", notes: "sample notes", archived: false, createdAt: at });
  releaseRepo.insert({ id: "release_a2", orgId: "org_acme", ownerId: "usr_alice", version: "sample version", notes: "sample notes", archived: false, createdAt: at });
  releaseRepo.insert({ id: "release_g1", orgId: "org_globex", ownerId: "usr_carol", version: "sample version", notes: "sample notes", archived: false, createdAt: at });
  componentRepo.insert({ id: "component_a1", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", lead: "sample lead", createdAt: at });
  componentRepo.insert({ id: "component_a2", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", lead: "sample lead", createdAt: at });
  componentRepo.insert({ id: "component_g1", orgId: "org_globex", ownerId: "usr_carol", name: "sample name", lead: "sample lead", createdAt: at });
  approvalRepo.insert({ id: "approval_a1", orgId: "org_acme", ownerId: "usr_alice", subject: "sample subject", state: "sample state", createdAt: at });
  approvalRepo.insert({ id: "approval_a2", orgId: "org_acme", ownerId: "usr_alice", subject: "sample subject", state: "sample state", createdAt: at });
  approvalRepo.insert({ id: "approval_g1", orgId: "org_globex", ownerId: "usr_carol", subject: "sample subject", state: "sample state", createdAt: at });
  pollRepo.insert({ id: "poll_a1", orgId: "org_acme", ownerId: "usr_alice", question: "sample question", closesOn: "sample closesOn", createdAt: at });
  pollRepo.insert({ id: "poll_a2", orgId: "org_acme", ownerId: "usr_alice", question: "sample question", closesOn: "sample closesOn", createdAt: at });
  pollRepo.insert({ id: "poll_g1", orgId: "org_globex", ownerId: "usr_carol", question: "sample question", closesOn: "sample closesOn", createdAt: at });
  checklistRepo.insert({ id: "checklist_a1", orgId: "org_acme", ownerId: "usr_alice", title: "sample title", items: "sample items", archived: false, createdAt: at });
  checklistRepo.insert({ id: "checklist_a2", orgId: "org_acme", ownerId: "usr_alice", title: "sample title", items: "sample items", archived: false, createdAt: at });
  checklistRepo.insert({ id: "checklist_g1", orgId: "org_globex", ownerId: "usr_carol", title: "sample title", items: "sample items", archived: false, createdAt: at });
  customFieldRepo.insert({ id: "custom-field_a1", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", kind: "sample kind", archived: false, createdAt: at });
  customFieldRepo.insert({ id: "custom-field_a2", orgId: "org_acme", ownerId: "usr_alice", name: "sample name", kind: "sample kind", archived: false, createdAt: at });
  customFieldRepo.insert({ id: "custom-field_g1", orgId: "org_globex", ownerId: "usr_carol", name: "sample name", kind: "sample kind", archived: false, createdAt: at });
}
