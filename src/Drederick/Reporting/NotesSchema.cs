namespace Drederick.Reporting;

/// <summary>
/// SQL schema and utilities for the notes feature in findings.db.
/// Notes allow CTF/lab operators to store flags, credentials, screenshots, and metadata.
/// </summary>
public static class NotesSchema
{
    /// <summary>
    /// Returns the CREATE TABLE and indices DDL for the notes table.
    /// Safe for idempotent execution with CREATE TABLE IF NOT EXISTS.
    /// </summary>
    public static string GetCreateTableDdl() => @"
CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY,
  title TEXT NOT NULL CHECK (length(trim(title)) > 0),
  content TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  created_by TEXT NOT NULL DEFAULT 'operator',
  
  is_flag BOOLEAN DEFAULT FALSE,
  flag_format TEXT,
  tags TEXT,
  category TEXT DEFAULT 'note' CHECK (category IN ('flag', 'credential', 'exploit', 'screenshot', 'command', 'note')),
  
  host_id TEXT,
  service_id INTEGER,
  
  file_data BLOB,
  file_name TEXT,
  file_mime_type TEXT,
  file_size INTEGER CHECK (file_size IS NULL OR file_size >= 0),
  
  source TEXT DEFAULT 'cli' CHECK (source IN ('cli', 'ui', 'import')),
  is_archived BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_notes_host_id ON notes(host_id);
CREATE INDEX IF NOT EXISTS idx_notes_service_id ON notes(service_id);
CREATE INDEX IF NOT EXISTS idx_notes_created_at ON notes(created_at);
CREATE INDEX IF NOT EXISTS idx_notes_is_flag ON notes(is_flag);
CREATE INDEX IF NOT EXISTS idx_notes_is_archived ON notes(is_archived);
CREATE INDEX IF NOT EXISTS idx_notes_category ON notes(category);

CREATE TRIGGER IF NOT EXISTS notes_update_timestamp
AFTER UPDATE ON notes
FOR EACH ROW
BEGIN
  UPDATE notes SET updated_at = datetime('now')
  WHERE id = NEW.id;
END;
";
}
