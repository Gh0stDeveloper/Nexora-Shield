package dev.nexora.shield.studio.ui

import java.nio.file.Path
import javax.swing.JFileChooser
import javax.swing.filechooser.FileNameExtensionFilter

fun chooseDirectory(): Path? {
    val chooser = JFileChooser()
    chooser.dialogTitle = "Select Android project"
    chooser.fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
    chooser.isMultiSelectionEnabled = false
    return if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
        chooser.selectedFile.toPath()
    } else {
        null
    }
}

fun chooseFile(
    description: String,
    vararg extensions: String,
): Path? {
    val chooser = JFileChooser()
    chooser.dialogTitle = description
    chooser.fileSelectionMode = JFileChooser.FILES_ONLY
    chooser.isMultiSelectionEnabled = false
    if (extensions.isNotEmpty()) {
        chooser.fileFilter = FileNameExtensionFilter(description, *extensions)
    }
    return if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
        chooser.selectedFile.toPath()
    } else {
        null
    }
}
