/**
 * Typed Tauri command wrappers.
 *
 * Every Tauri IPC command the frontend invokes goes through this module so
 * the types stay in one place. Keeps the rest of the frontend free of
 * `invoke<...>()` boilerplate.
 *
 * Mirror of src-tauri/src/commands.rs — if you add a command there, add the
 * wrapper here.
 */
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import type { AuditDocument } from "./audit-types";

export const tauri = {
  /**
   * Returns the running Studio version string (matches Cargo.toml).
   * Used by the header version badge + auto-updater logic.
   */
  async getAppVersion(): Promise<string> {
    return invoke<string>("get_app_version");
  },

  /**
   * Opens the macOS folder-picker, then runs an audit against the picked
   * folder. Returns an AUDIT.json-shaped document or null if the user
   * cancelled the picker.
   *
   * v0.1.0-pre.0: this is a stub that returns a hand-crafted demo result.
   * Real audit wires through to the lictor-core Rust crate (TODO Oct 1).
   */
  async pickFolderAndAudit(): Promise<AuditDocument | null> {
    const folder = await open({
      directory: true,
      multiple: false,
      title: "Select a project folder to audit",
    });

    if (!folder || Array.isArray(folder)) return null;

    return invoke<AuditDocument>("run_audit", { path: folder });
  },

  /**
   * Loads an AUDIT.json file from disk for the universal-translator view.
   * Validates against AUDIT.schema.json before returning.
   * (TODO milestone Nov 15)
   */
  async importAuditJson(): Promise<AuditDocument | null> {
    const file = await open({
      directory: false,
      multiple: false,
      filters: [{ name: "AUDIT.json", extensions: ["json"] }],
      title: "Import AUDIT.json",
    });

    if (!file || Array.isArray(file)) return null;

    return invoke<AuditDocument>("import_audit_json", { path: file });
  },

  /**
   * Writes the current findings to AUDIT.json on disk.
   * (TODO milestone Nov 15)
   */
  async exportAuditJson(doc: AuditDocument): Promise<string> {
    return invoke<string>("export_audit_json", { doc });
  },
};
