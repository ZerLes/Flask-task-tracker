function mce_readonly_toggle(tinymce) {
	menu_bar = tinymce.activeEditor.editorContainer.getElementsByClassName("tox-editor-header")[0]
	if (!menu_bar.hidden) {
		menu_bar.hidden = true;
		tinymce.activeEditor.setMode('readonly');
		}
	else {
		menu_bar.hidden = false;
		tinymce.activeEditor.setMode('design');
		}
	}
