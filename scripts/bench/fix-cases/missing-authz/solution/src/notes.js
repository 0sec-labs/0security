// A tiny notes service. `user` is the signed-in user: { id, role }.
export class NoteStore {
  constructor() { this.notes = new Map(); this.next = 1; }

  create(user, text) {
    const id = this.next++;
    this.notes.set(id, { id, ownerId: user.id, text });
    return id;
  }

  #authorized(user, id) {
    const note = this.notes.get(id);
    if (!note) throw new Error("not found");
    if (note.ownerId !== user.id && user.role !== "admin") throw new Error("not found");
    return note;
  }

  get(user, id) {
    return this.#authorized(user, id);
  }

  remove(user, id) {
    this.#authorized(user, id);
    this.notes.delete(id);
  }

  list(user) {
    return [...this.notes.values()].filter(n => n.ownerId === user.id);
  }
}
