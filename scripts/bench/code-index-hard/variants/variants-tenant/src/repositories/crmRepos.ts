import { Repo } from "../lib/store";
import type { Contact, Deal, Lead, Campaign, Activity, Note, Tag } from "../models/crm";

export const contactRepo = new Repo<Contact>("contacts");
export const dealRepo = new Repo<Deal>("deals");
export const leadRepo = new Repo<Lead>("leads");
export const campaignRepo = new Repo<Campaign>("campaigns");
export const activityRepo = new Repo<Activity>("activities");
export const noteRepo = new Repo<Note>("notes");
export const tagRepo = new Repo<Tag>("tags");
