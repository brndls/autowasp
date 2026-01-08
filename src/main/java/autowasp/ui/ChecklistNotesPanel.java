/*
 * Copyright (c) 2026 Autowasp
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package autowasp.ui;

import autowasp.managers.NoteManager;
import autowasp.notes.Note;
import autowasp.notes.NoteChangeListener;
import java.awt.*;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.MatteBorder;

/**
 * Side panel for displaying and managing session notes.
 */
public class ChecklistNotesPanel extends JPanel implements NoteChangeListener {
    private final transient NoteManager noteManager;
    private String currentWstgId;

    private final JLabel headerLabel;
    private final JPanel notesListPanel;
    private final JScrollPane scrollPane;

    private final JPanel editorPanel;
    private final JTextArea noteTextArea;
    private final JButton saveButton;
    private final JButton addButton;

    private transient Note editingNote;

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
            .withZone(ZoneId.systemDefault());

    public ChecklistNotesPanel(NoteManager noteManager) {
        this.noteManager = noteManager;
        this.noteManager.addChangeListener(this);

        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(5, 5, 5, 5));

        // Header
        headerLabel = new JLabel("📝 Notes: No selection");
        if (headerLabel.getFont() != null) {
            headerLabel.setFont(headerLabel.getFont().deriveFont(Font.BOLD, 14f));
        }
        headerLabel.setBorder(new EmptyBorder(5, 5, 10, 5));
        add(headerLabel, BorderLayout.NORTH);

        // Notes List
        notesListPanel = new JPanel();
        notesListPanel.setLayout(new BoxLayout(notesListPanel, BoxLayout.Y_AXIS));

        scrollPane = new JScrollPane(notesListPanel);
        scrollPane.setBorder(null);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        add(scrollPane, BorderLayout.CENTER);

        // Editor Panel
        editorPanel = new JPanel(new BorderLayout(5, 5));
        editorPanel.setBorder(new EmptyBorder(10, 5, 5, 5));

        noteTextArea = new JTextArea(5, 20);
        noteTextArea.setLineWrap(true);
        noteTextArea.setWrapStyleWord(true);

        JScrollPane editorScrollPane = new JScrollPane(noteTextArea);
        editorPanel.add(editorScrollPane, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.TRAILING));
        saveButton = new JButton("Save");
        JButton cancelButton = new JButton("Cancel");

        saveButton.addActionListener(e -> saveNote());
        cancelButton.addActionListener(e -> hideEditor());

        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);
        editorPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Add Button
        addButton = new JButton("+ Add Note");
        addButton.addActionListener(e -> showEditor(null));

        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(addButton, BorderLayout.NORTH);
        bottomPanel.add(editorPanel, BorderLayout.CENTER);

        add(bottomPanel, BorderLayout.SOUTH);

        editorPanel.setVisible(false);
        addButton.setEnabled(false);
    }

    public void setSelectedWstgId(String wstgId) {
        this.currentWstgId = wstgId;
        if (wstgId == null) {
            headerLabel.setText("📝 Notes: No selection");
            addButton.setEnabled(false);
        } else {
            headerLabel.setText("📝 Notes: " + wstgId);
            addButton.setEnabled(true);
        }
        hideEditor();
        refreshNotes();
    }

    @Override
    public void onNotesChanged() {
        SwingUtilities.invokeLater(this::refreshNotes);
    }

    private void refreshNotes() {
        notesListPanel.removeAll();

        if (currentWstgId != null) {
            List<Note> notes = noteManager.getNotesByWstgId(currentWstgId);
            for (Note note : notes) {
                notesListPanel.add(createNoteCard(note));
                notesListPanel.add(Box.createVerticalStrut(10));
            }
        }

        notesListPanel.revalidate();
        notesListPanel.repaint();
    }

    private JPanel createNoteCard(Note note) {
        JPanel card = new JPanel(new BorderLayout(5, 5));
        card.setBorder(BorderFactory.createCompoundBorder(
                new MatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                new EmptyBorder(5, 5, 5, 5)));

        JTextArea contentArea = new JTextArea(note.content());
        contentArea.setEditable(false);
        contentArea.setLineWrap(true);
        contentArea.setWrapStyleWord(true);
        contentArea.setOpaque(false);
        if (card.getFont() != null) {
            contentArea.setFont(card.getFont().deriveFont(12f));
        }

        card.add(contentArea, BorderLayout.CENTER);

        JPanel footer = new JPanel(new BorderLayout());
        footer.setOpaque(false);

        JLabel timeLabel = new JLabel(DATE_FORMATTER.format(note.updatedAt()));
        if (timeLabel.getFont() != null) {
            timeLabel.setFont(timeLabel.getFont().deriveFont(Font.ITALIC, 10f));
        }
        timeLabel.setForeground(Color.GRAY);
        footer.add(timeLabel, BorderLayout.WEST);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        actions.setOpaque(false);

        JButton editBtn = new JButton("Edit");
        editBtn.setMargin(new Insets(2, 5, 2, 5));
        if (editBtn.getFont() != null) {
            editBtn.setFont(editBtn.getFont().deriveFont(10f));
        }
        editBtn.addActionListener(e -> showEditor(note));

        JButton deleteBtn = new JButton("Delete");
        deleteBtn.setMargin(new Insets(2, 5, 2, 5));
        if (deleteBtn.getFont() != null) {
            deleteBtn.setFont(deleteBtn.getFont().deriveFont(10f));
        }
        deleteBtn.addActionListener(e -> deleteNote(note));

        actions.add(editBtn);
        actions.add(deleteBtn);
        footer.add(actions, BorderLayout.EAST);

        card.add(footer, BorderLayout.SOUTH);

        return card;
    }

    private void showEditor(Note note) {
        this.editingNote = note;
        if (note != null) {
            noteTextArea.setText(note.content());
            saveButton.setText("Update");
        } else {
            noteTextArea.setText("");
            saveButton.setText("Save");
        }
        editorPanel.setVisible(true);
        addButton.setVisible(false);
        noteTextArea.requestFocusInWindow();
        revalidate();
        repaint();
    }

    private void hideEditor() {
        this.editingNote = null;
        editorPanel.setVisible(false);
        addButton.setVisible(true);
        revalidate();
        repaint();
    }

    private void saveNote() {
        String content = noteTextArea.getText().trim();
        if (content.isEmpty()) {
            return;
        }

        if (editingNote != null) {
            noteManager.updateNote(editingNote.withUpdatedContent(content));
        } else if (currentWstgId != null) {
            noteManager.addNote(Note.create(content, currentWstgId));
        }

        hideEditor();
    }

    private void deleteNote(Note note) {
        if (confirmDelete()) {
            noteManager.deleteNote(note.id());
        }
    }

    protected boolean confirmDelete() {
        int result = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to delete this note?",
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION);
        return result == JOptionPane.YES_OPTION;
    }
}
