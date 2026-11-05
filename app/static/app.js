"use strict";
let accessToken = null; // Memory only: refresh or sign out clears the token.
const status = document.querySelector("#status");
async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {"Content-Type": "application/json", ...(accessToken ? {Authorization: `Bearer ${accessToken}`} : {})},
  });
  const data = await response.json();
  if (!response.ok) throw new Error(`${response.status}: ${data.error}`);
  return data;
}
async function loadNotes(q = "") {
  const data = await api(`/api/notes?q=${encodeURIComponent(q)}`);
  const container = document.querySelector("#notes");
  container.replaceChildren();
  for (const note of data.notes) {
    const article = document.createElement("article");
    const heading = document.createElement("h3");
    const body = document.createElement("p");
    heading.textContent = note.title;
    body.textContent = note.body; // Treat untrusted content as text, never HTML.
    article.append(heading, body);
    container.append(article);
  }
  if (!data.notes.length) container.textContent = "No notes found.";
}
document.querySelector("#login-form").addEventListener("submit", async event => {
  event.preventDefault();
  accessToken = null;
  document.querySelector("#notes").replaceChildren();
  try {
    const form = new FormData(event.target);
    const result = await api("/auth/login", {method: "POST", body: JSON.stringify(Object.fromEntries(form))});
    accessToken = result.access_token;
    event.target.elements.password.value = "";
    status.textContent = `Signed in as ${form.get("username")} · token lifetime ${result.expires_in / 60} minutes`;
    await loadNotes();
  } catch (error) { status.textContent = error.message; }
});
document.querySelector("#note-form").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    await api("/api/notes", {method: "POST", body: JSON.stringify(Object.fromEntries(new FormData(event.target)))});
    status.textContent = "Note saved (201 Created).";
    event.target.reset();
    await loadNotes();
  } catch (error) { status.textContent = error.message; }
});
document.querySelector("#search-form").addEventListener("submit", async event => {
  event.preventDefault();
  try { await loadNotes(new FormData(event.target).get("q")); }
  catch (error) { status.textContent = error.message; }
});
document.querySelector("#logout").addEventListener("click", () => {
  accessToken = null;
  status.textContent = "Signed out locally.";
  document.querySelector("#notes").textContent = "Sign in to see your notes.";
});
