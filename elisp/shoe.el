;; -*- lexical-binding: t; lisp-indent-offset: 1 -*-
;; Eval before cursor is C-x C-e

(message "Trying to load init.el by vg...")
(defun vg-message (fmt &rest args)
 (apply 'message (propertize fmt 'face '(:background "#A0FFA0")) args))
(setq force-load-messages t)
(require 'subr-x)

;;
;;     BEHAVIOR
;;     ````````
;;

(setq default-major-mode 'text-mode transient-mark-mode t)
;;загружается молча
(setq inhibit-startup-message t initial-scratch-message nil)
(tool-bar-mode -1)
;;гладкий скроллинг с полями
(setq scroll-conservatively 100 scroll-preserve-screen-position 't
	  scroll-margin 0)
;; show column & line numbers in status bar
(setq column-number-mode t line-number-mode t)

;; Start off in "C:/home" dir.
(cd "~/")
(setq my-author-name (getenv "USER") user-full-name (getenv "USER"))
(recentf-mode 1); Recent files in menu
;;
;;Создание резервных копий редактируемых файлов (Backup)
;;
(setq
   backup-by-copying t      ; don't clobber symlinks
   backup-directory-alist '(("." . "~/.backup"))    ; don't litter my fs tree
   delete-old-versions t
   kept-new-versions 6
   kept-old-versions 2
   version-control t       ; use versioned backups
   auto-save-file-name-transforms
   `((".*" ,temporary-file-directory t)))

;;
;;мышка...
;;
;; Scroll Bar gets dragged by mouse butn 1
(global-set-key [vertical-scroll-bar down-mouse-1] 'scroll-bar-drag)
;; Paste at point NOT at cursor
(setq mouse-yank-at-point 't)
;;колесо мышки
(mouse-wheel-mode 1)
(setq mouse-wheel-scroll-amount '(5 ((shift) . 1) ((control) . nil)))
(setq mouse-wheel-progressive-speed t)
;;
;;Настройка поведения редактора "как в Windows"
;;
;;настройка клавиатуры как в Windows
;;
;;Delete (and its variants) delete forward instead of backward.
;;C-Backspace kills backward a word (as C-Delete normally would).
;;M-Backspace does undo.
;;Home and End move to beginning and end of line
;;C-Home and C-End move to beginning and end of buffer.
;;C-Escape does list-buffers." 
(if (fboundp 'pc-bindings-mode) (pc-bindings-mode))
;;Настройка выделения "как в Windows"
(if (fboundp 'pc-selection-mode) (pc-selection-mode))
;;
;;Установка режима CUA
;;поддержка Ctr-c,v,x,d как в windows
;;
(require 'cua-base)
(cua-mode t)
;;установка режимов работы курсора через CUA
(setq cua-normal-cursor-color "black")
(setq cua-overwrite-cursor-color "red")
(setq cua-read-only-cursor-color "green") 
;; always end a file with a newline
(setq require-final-newline t)
(delete-selection-mode t) ; <del> удаляет выделенный текст

;;
;;     GENERAL KEYS
;;     ``````` ````

(defun vg-backward-delete-word ()
 "Delete word without changing clipboard. TODO The same forward"
 (interactive)
 (delete-region (point) (progn (forward-word -1) (point))))

(global-set-key [home] 'beginning-of-line)
(global-set-key [end] 'end-of-line)
; Workaround for windows remote terminals
(global-set-key [select] 'end-of-line)
(global-set-key [A-home] 'beginning-of-buffer)
(global-set-key [A-end] 'end-of-buffer)
(global-set-key [\C-home] 'beginning-of-buffer)
(global-set-key [\C-end] 'end-of-buffer)
(define-key global-map [s-home] 'beginning-of-buffer)
(define-key global-map [s-end] 'end-of-buffer)
(define-key global-map (kbd "s-[") 'backward-sexp)
(define-key global-map (kbd "s-]") 'forward-sexp)
(global-set-key (kbd "A-k") 'kill-line)
(defun vg-mark-whole-buffer () (interactive)
 (setq transient-mark-mode '(only . t))
 (mark-whole-buffer))
(define-key global-map (kbd "C-a") 'vg-mark-whole-buffer)
(define-key global-map (kbd "s-a") 'vg-mark-whole-buffer)

;; [C-f] didn't work
(define-key global-map (kbd "C-f") 'isearch-forward)
(define-key global-map (kbd "s-t") 'isearch-backward)
;; TODO Breaks all Alt key combinations
;; Trying to bind them throws:
;; "Key sequence ESC ESC starts with non-prefix key ESC"
;; (define-key global-map (kbd "ESC") 'keyboard-quit)
;; TODO 2: keyboard-quit is the original C-g,
;; but abort-recursive-edit (C-]) works better.
;; Need to C-g 3 times to get out of isearch. Smth should be done
(define-key global-map (kbd "ESC ESC") 'keyboard-quit)
(define-key global-map (kbd "s-g") 'abort-recursive-edit)
;; Standard Mac 'other window' key
(global-set-key (kbd "A-'") 'other-window)
(global-set-key [M-tab] 'other-window)
(global-set-key [C-tab]  'other-window)
(global-set-key (kbd "C-=") 'switch-to-buffer)
;;(global-set-key [C-x] 'clipboard-kill-region)
(global-set-key (kbd "C-v") 'cua-paste)

;; Completion
;; [s-\`] [s-/] do not work!
(define-key global-map (kbd "s-/") 'dabbrev-expand)
(global-set-key (kbd "A-/") 'dabbrev-expand)
;; Use key from Vim
(global-set-key (kbd "C-p") 'dabbrev-expand)
(global-set-key (kbd "s-p") 'dabbrev-expand)
(global-set-key (kbd "C-/") 'dabbrev-expand)
;; Putting this next to C-p to return to previous completion
(define-key global-map (kbd "C-o") 'undo)
(define-key global-map (kbd "C-0")
 (lambda () (interactive) (insert " ")))
;; End of `completion`

;; Code navigation
(global-set-key [A-M-down] 'ft-at-point)
(global-set-key [A-M-S-down] 'ft-other-window-at-point)
(global-set-key [A-C-M-down] 'ft-other-window-at-point)
(global-set-key [A-M-next] 'ft-other-window-at-point)
(global-set-key [A-M-up] 'pop-tag-mark)
; [A-M-/] didn't work
(global-set-key (kbd "A-M-/") 'ft-next)
(define-key global-map [M-s-up] 'pop-tag-mark)
(define-key global-map [M-s-down] 'ft-at-point)
;; That's impossible to thumb type
(define-key global-map [C-M-s-down] 'ft-other-window-at-point)
;; That's hard to remember
(define-key global-map [M-s-return] 'ft-other-window-at-point)
;; Mac
(define-key global-map (kbd "M-s-÷") 'ft-next)
;; Linux
(define-key global-map (kbd "M-s-/") 'ft-next)
;; Temporary until I can't make VNC work right. Right now
;; Cmd is M- and alt doesn't do anything
(define-key global-map [M-next] 'ft-at-point)
(define-key global-map [M-prior] 'pop-tag-mark)
;; End of code navigation

(define-key global-map [f1] 'man)
(define-key global-map (kbd "C-\\")
 (lambda () (interactive)
  (vg-message "Keyboard language switch disabled")))
(define-key global-map [insert]
 (lambda () (interactive)
  (vg-message "Overwrite mode switch disabled")))
(define-key global-map (kbd "s-b") 'end-of-buffer)
(define-key global-map (kbd "C-b") 'end-of-buffer)
(define-key global-map [f7] 'google-line)
(define-key global-map [f9] 'gscholar-line)
(define-key global-map [f12] 'vg-gh-search-line)
;; Adjacent built-in bindings on Mac:
;; s-n = New window, s-m = Minimize, s-u = Revert, s-k = Close file 
(define-key global-map (kbd "s-o") 'find-file)
;; Use with Shift on XFCE
(define-key global-map (kbd "s-r") 'revert-buffer)
(define-key global-map [s-delete]
 (define-key global-map [s-kp-delete]
  'kill-current-buffer))
;; Make it the same as Firefox 'kill tab' on Mac
(define-key global-map (kbd "s-w") 'kill-current-buffer)
(define-key global-map [C-backspace] 'vg-backward-delete-word)
(define-key global-map [M-backspace] 'vg-backward-delete-word)
(define-key global-map [s-backspace] 'vg-backward-delete-word)
;; Use a key from shell
(define-key global-map (kbd "C-w") 'vg-backward-delete-word)
(define-key global-map [s-left] 'previous-buffer)
(define-key global-map [s-right] 'next-buffer)
;; Norton Commander had Ctrl-U, but it's used for another thing,
;; and Flag-U does something else on Mac, so it's Alt-U for now
(define-key global-map (kbd "M-u") 'window-swap-states)
;; Add Flag-U too on Linux
(if (equal window-system 'x)
 (define-key global-map (kbd "s-u") 'window-swap-states))
;; TODO mimic vscode
(define-key global-map (kbd "s-1") 'other-window)
(define-key global-map (kbd "s-2") 'other-window)
;; Go to the notes
(define-key global-map (kbd "s-3")
 (lambda () (interactive) (find-file "~/20note.org")))
(define-key global-map (kbd "s-4")
 (lambda () (interactive) (switch-to-buffer "*compilation*")))
(define-key global-map (kbd "s-5")
 (lambda () (interactive) (find-file "~")))
(define-key global-map (kbd "C-1")
 (lambda () (interactive) (find-file "~")))
(define-key global-map (kbd "s-8") 'vg-insert-todays-date)
(defun vg-insert-todays-date () (interactive)
 (insert (format-time-string "\n* %c. Subject\n")))
(put 'vg-insert-todays-date 'delete-selection t)

;; TODO Set C-; to dabbrev expand? Bc its near space
(global-set-key [M-down] 'move-text-down)
(global-set-key [M-up] 'move-text-up)
(define-key global-map [s-return]
 (lambda () (interactive) (cycle-spacing -1)))
;; A key from ncedit.exe
(define-key global-map [f4] 'query-replace)
(define-key global-map (kbd "M-RET") 'dired-find-file-other-window)
(define-key global-map (kbd "M-q") 'vg-fill-lines-to-end)

(defun vg-trash-buffer-file () (interactive)
 ;; TODO Make it work 
 (save-buffer)
 (if (with-current-buffer "*Messages*"
	  (let ((buffer-read-only nil))
	   (call-process "gio" nil t nil "trash" "TODO: confirm")))
  (vg-message "TODO Make a function to trash the file + close buffer")
  (kill-buffer)))
(define-key global-map [f8] 'vg-trash-buffer-file)

(defun vg-case-insensitive-isearch () (interactive)
 (let ((case-fold-search t))
  (command-execute 'isearch-forward)))
(define-key global-map (kbd "s-i") 'vg-case-insensitive-isearch)

;; Compile/grep
(define-key global-map (kbd "s-q") 'compile)
;; Need some Ctrl key for compile to easily go to C-r
(define-key global-map "\C-d" 'compile)
(define-key global-map (kbd "C-`") 'compile)
(define-key global-map [s-f9] 'compile)
;; TODO `recompile` doesn't restore CWD of the last compile 
(define-key global-map (kbd "s-y") 'recompile)
(define-key global-map (kbd "s-s")
 (lambda () (interactive)
  (let* ((src
		  (if (buffer-file-name)
		   (file-name-directory (buffer-file-name))
		   default-directory))
		 (root (locate-dominating-file src ".git")))
   (grep-apply-setting 'grep-command
	;; TODO: quote + resolve '~'
	(format "cd %s && git grep --recurse-submodules -n " root)))
  (command-execute 'grep)))
(define-key global-map (kbd "s-d") 'vg-goto-git-root)
(defun vg-goto-git-root () (interactive)
 (let* ((src
		 (if (buffer-file-name)
		  (file-name-directory (buffer-file-name))
		  default-directory))
		(root (locate-dominating-file src ".git")))
  (if root
   (find-file root)
   (vg-message "'.git' directory not found for '%s'" src))))
(define-key global-map (kbd "M-s--") 'vg-up-dir)
(define-key global-map [M-s--] 'vg-up-dir)
(define-key global-map [s-f11] 'vg-up-dir)
(defun vg-up-dir () (interactive)
 (let ((p (or (buffer-file-name) default-directory)))
  (find-file (file-name-directory (directory-file-name p)))))

(global-set-key (kbd "ESC <up>") 'previous-error)
(define-key global-map [s-up] 'previous-error)
(define-key global-map [s-down] 'next-error)
;; A key from Finder
(define-key global-map (kbd "M-f") 'tracker-search)
(define-key global-map (kbd "s-f") 'tracker-search)

(define-key global-map (kbd "s-l") 'vg-run-paragraph)
(define-key global-map (kbd "C-l") 'vg-run-paragraph)
(define-key global-map (kbd "M-l") 'vg-run-paragraph)
(define-key global-map (kbd "C-.")
 (lambda () (interactive) (save-excursion (vg-run-line))))
(defun vg-run-paragraph () (interactive)
 (save-excursion
  (while
   (not (string-empty-p (string-trim (thing-at-point 'line t))))
   (previous-line))
  (next-line)
  (vg-run-line)))

(define-key global-map (kbd "C-,") 'vg-insert-compile-command)
(defun vg-insert-compile-command () (interactive)
 (let ((dir (with-current-buffer "*compilation*" default-directory)))
  (insert (format "cd %s &&\\\n %s" dir (car compile-history)))))

(defun vg-newterm-compile () (interactive)
 (let ((cmd (read-shell-command "Command (+window): " compile-command
             'compile-history)))
  (compilation-start
   (format "xfce4-terminal --hold --execute %s" cmd))))
(define-key global-map [f5] 'vg-newterm-compile)
(define-key global-map (kbd "s-j") 'vg-newterm-compile)

(defun vg-compile-new-buf () (interactive)
 "TODO Write function that renames *compilation* to something unique
and starts new compile. Alternatively, start new compile as
*compilation-ID*")

(defun vg-insert-current-file-path () (interactive)
 (insert
  (with-current-buffer (window-buffer (minibuffer-selected-window))
   (or buffer-file-name default-directory))))
(put 'vg-insert-current-file-path 'delete-selection t)
(define-key global-map (kbd "C-'") 'vg-insert-current-file-path)
(define-key global-map (kbd "s-`") 'vg-insert-current-file-path)
;; Another key from Norton Commander
;; TODO Doesn't work
(define-key global-map [(control return)] 'vg-insert-current-file-path)

;; XFCE overrides Alt-F7, also Alt-F1 F2 etc.
(global-set-key [M-f7]  'find-name-dired) 
(global-set-key [s-f7]  'find-name-dired) 
(define-key global-map [f6] 'rename-buffer)
(define-key global-map [s-escape] 'rename-buffer)

(when (fboundp 'osx-key-mode)
 (define-key osx-key-mode-map [(end)] 'end-of-line)
 (define-key osx-key-mode-map [(home)] 'beginning-of-line)
 (define-key osx-key-mode-map [M-up] 'backward-paragraph)
 (define-key osx-key-mode-map [M-down] 'forward-paragraph)
 (define-key osx-key-mode-map `[(,osxkeys-command-key up)]
  'previous-error)
 (define-key osx-key-mode-map `[(,osxkeys-command-key down)] 'next-error)
 (define-key osx-key-mode-map `[(meta z)] 'aquamacs-undo)
 (define-key osx-key-mode-map `[(meta c)] 'clipboard-kill-ring-save)
 (define-key osx-key-mode-map `[(meta v)] 'cua-paste)
 (define-key osx-key-mode-map `[(,osxkeys-command-key i)] 'test)
 (define-key osx-key-mode-map (kbd "A-;")
  (lambda () (interactive) (vg-message "Spell check disabled")))
 ;; latvian keyboard workaround 
 (define-key osx-key-mode-map (kbd "M-'")
  (lambda () (interactive) (insert "`"))))

(define-key global-map (kbd "s-=")
 (lambda () (interactive) (text-scale-increase 1)))
(define-key global-map (kbd "s--")
 (lambda () (interactive) (text-scale-increase -1)))

(when (and (not (fboundp 'osx-key-mode)) (equal window-system 'ns))
  ;; latvian keyboard workaround 
  (define-key global-map (kbd "M-'")
	(lambda () (interactive) (insert "`")))
  (let ((size 10) (i 0) name
		(fonts ["Menlo" "Courier" "Monaco" "PT Mono" "Andale Mono"]))
	(defun vg-update-font (ns ni)
	  (setq size ns i (% ni (length fonts)))
	  (setq name (format "%s-%d" (aref fonts i) size))
	  (set-frame-font name t)
	  (vg-message "Font: %s" name))
	(define-key global-map (kbd "s-=")
	  (lambda () (interactive) (vg-update-font (+ 1 size) i)))
	(define-key global-map (kbd "s--")
	  (lambda () (interactive) (vg-update-font (- size 1) i)))
	(define-key global-map (kbd "s-0")
	  (lambda () (interactive) (vg-update-font size (1+ i))))
   (vg-update-font size i)))

(defmacro Vg-with-cmd-output (cmd_ &rest body)
 `(let (output status (cmd ,cmd_))
   (with-temp-buffer
	(vg-message "Running %s..." cmd)
	(setq status 
	 (apply 'call-process (car cmd) nil (current-buffer)
	  nil (cdr cmd)))
	(setq output
	 (string-trim
	  (buffer-substring-no-properties (point-min) (point-max)))))
   (if (/= 0 status)
	;; TODO
	;; Output can be too big for the status console.
	;; Need a version of this that will show output in a frame
	(vg-message "Output: %s\n%s exited with status %s"
	 output cmd status)
	,@body)))

(defun vg-diff-stash-file () (interactive)
 "In diff mode: reversibly undo the changes to file at point"
 (let* ((buf (car (diff-find-source-location)))
		(path (buffer-file-name buf)) (dir default-directory)
		(sp (point)))
  (Vg-with-cmd-output
   (list "git" "stash" "push" "-m"
	(format "File '%s' saved by vg-diff-stash-file" path) "--" path)
   (vg-message "%s exited with status %s" cmd status))
  (revert-buffer)
  ;; TODO Restore pos doesn't work 
  (vg-message "Pos=%s" sp)
  (goto-char sp)))

(require 'diff-mode)
(define-key diff-mode-map [delete] 'vg-diff-stash-file)
;; Mac Fn+Backspace
(define-key diff-mode-map [kp-delete] 'vg-diff-stash-file)
(define-key diff-mode-map "c"
 (lambda () (interactive)
  (setq-local compile-command "git commit")
  (command-execute 'compile)))
 
(defun ft-at-point () "AKA go to def" (interactive)
	   (find-tag (find-tag-default)))

(defun ft-next () "Other def" (interactive)
	   (find-tag () t))

(defun ft-other-window-at-point () "Set other window to def"
 (interactive)
 (let ((q (find-tag-default)))
  (if q
   (find-tag-other-window (find-tag-default))
   (vg-message "No names at point"))))

(defun Vg-current-word-or-selection ()
  (format "\"%s\""
   (if (use-region-p)
	(string-trim (buffer-substring-no-properties
				  (region-beginning) (region-end)))
	(or (find-tag-default) ""))))

(defun google-at-point () (interactive)
 (Vg-search-at-point "https://www.google.com/search?q=%s"))

(define-key global-map [f4]
 (lambda () (interactive)
  (Vg-search-current-line
   "https://www.youtube.com/results?search_query=%s"
   " -\"hey delphi\"\
  -\"Roel Van de Paar\" -iluvatar1 -\"A To Z Hacks\" -\"Quick Notepad\
  Tutorial\" -\"Luke Chaffey\" -\"News Source Crawler\"")))

(define-key global-map [s-f4]
 (lambda () (interactive)
  (Vg-search-current-line 
   "https://www.opensubtitles.org/en/search2/sublanguageid-ger/moviename-%s")))

(defun Vg-search-at-point (tmpl)
 (let
  ((q (Vg-current-word-or-selection)))
  (if q
   (Vg-open-browser (format tmpl q))
   (vg-message "No current word or selection")))) 

(defun google-line () (interactive)
 (Vg-search-current-line "https://www.google.com/search?q=%s"))

(defun Vg-get-query-from-current-line ()
 (string-trim (replace-regexp-in-string "[[] []]\\|Q:" ""
  (Vg-get-current-line-escaped))))

(defun Vg-search-current-line (tmpl &optional suffix)
 (if (use-region-p)
  (Vg-search-at-point tmpl)
  (Vg-open-browser
   (format tmpl
	(url-hexify-string
	 (string-trim
	  (concat (Vg-get-query-from-current-line) suffix)))))))

(defun gscholar-line () (interactive)
 (Vg-search-current-line "https://scholar.google.com/scholar?q=%s"))

(defun vg-gh-search-line () (interactive)
 (Vg-search-current-line "https://github.com/search?q=%s&type=code"))

(defun Vg-open-browser (url)
 (if (equal window-system 'ns)
  (vg-open url)
  (start-process url "*Messages*" "firefox" url)))

(defun vg-open (x)
 (let ((cmd (append (if (equal window-system 'ns) '("open")
					 '("setsid" "nohup" "xdg-open")) (list x))))
  ;;(apply 'Vg-start-process cmd)
  (Vg-with-cmd-output cmd)
  ))

(defun Vg-start-process (&rest cmd)
 (vg-message "Running %s" cmd)
 (apply 'start-process (format "%s" cmd) "*Messages*" cmd))

(defun open () (interactive)
 (vg-open (expand-file-name (or buffer-file-name default-directory))))

;;
;;    APPEARANCE
;;    ``````````
;;

(setq-default tab-width 4)
(setq font-lock-maximum-decoration t)
(global-font-lock-mode 1) ; for syntax highlighting


;; Выделение парных скобок
(show-paren-mode 1)
(setq show-paren-style 'expression);выделять все выражение в скобках
(when (and (equal window-system 'x)
	   (not (fboundp 'touch-screen-scroll)))
 (define-key global-map [touchscreen-begin] 'vg-start-scroll-touchscreen)
 (define-key global-map [touchscreen-update] 'vg-scroll-touchscreen)
 (define-key global-map [touchscreen-end] 'vg-reset-touchscreen)

 (defvar vg-last-y 0)
 (defun vg-start-scroll-touchscreen (event) (interactive "e")
  (posn-set-point (cdr (event-end event))))
 
 (defun vg-scroll-touchscreen () (interactive)
  (let* ((coords (nth 3 (car (car (cdr last-input-event)))))
		 (y (cdr coords))
		 (dy (- vg-last-y y)))
   (when (> vg-last-y 0)
	(if (> dy 0)
	 (pixel-scroll-precision-scroll-down-page dy)
	 (pixel-scroll-precision-scroll-up-page (- dy))))
   (setq vg-last-y y)))
 
 (defun vg-reset-touchscreen (event) (interactive "e")
  (setq vg-last-y 0)
  (let ((p (cdr (event-end event))))
   (when nil
	(vg-message "e = %s" event)
	(vg-message "event-end e = %s" (event-end event))
	(vg-message "event-start e = %s" (event-start event))
	(vg-message "cdr last-input-event = %s" (cdr last-input-event)))
   (posn-set-point p)))
 )

(when (equal window-system 'x) 
 (pixel-scroll-mode)
 (add-to-list 'default-frame-alist
             '(font . "Monospace-10.9"))
	;; "Bitstream Vera Sans Mono-9"
 (set-frame-font "Monospace-10.9"))
  ;; "Courier New 9")

;(set-cursor-color "red")
(blink-cursor-mode -10)

;; 
;;    КОДИРОВКИ
;;    `````````
;;
;; Использовать окружение UTF-8
(set-language-environment 'UTF-8)
(set-buffer-file-coding-system 'utf-8-unix)
(set-default-coding-systems 'utf-8-unix)
(set-terminal-coding-system 'utf-8-dos)
(set-selection-coding-system 'utf-8-dos)
(setq coding-system-for-read 'utf-8)

;; 
;;     PROGRAMMING
;;     ```````````
;;

;; Here we rely on load path having been set in .emacs.
;; TODO Use path of this file
(autoload 'wikipedia-mode "wikipedia-mode.el"
  "Major mode for editing documents in Wikipedia markup." t)
(autoload 'rust-mode "rust-mode.el"
  "From https://github.com/rust-lang/rust-mode.git" t)
(setq rust-cargo-bin "/Users/vg/.cargo/bin/cargo")
(autoload 'haskell-mode "haskell-mode-2.8.0/haskell-site-file" "HM" t)
(add-hook 'haskell-mode-hook 'turn-on-haskell-indentation)
(prog1
 (load "../compact-blame/compact-blame.el")
 (setq compact-blame-bg1 "rainbow")
 (setq compact-blame-bg2 "rainbow2")
 (setq compact-blame-format "%Y%x%.%#")
 (setq compact-blame-light-coeff 1050)
 (setq compact-blame-name-limit 4))
(load "markdown-mode/markdown-mode.el")
(add-hook 'markdown-mode-hook 'word-wrap-whitespace-mode)
(add-hook 'markdown-mode-hook 'Vg-tune-md)

(defun Vg-tune-md ()
 (setq-local search-upper-case nil))

(defun vg-tune-c ()
  (setq c-basic-offset 4
		tab-width 2
		js-indent-level 4
		indent-tabs-mode t
;		tags-case-fold-search nil
		)
  (c-set-offset 'arglist-intro '+)
  (c-set-offset 'arglist-cont-nonempty '+)
  (c-set-offset 'arglist-close 0)
 (c-set-offset 'innamespace 0)
 ;;(c-set-offset 'case-label '+)
 (c-set-offset 'brace-list-intro '+)
 (c-set-offset 'brace-list-entry 0)
  (abbrev-mode -1)
  (vg-message
   "C mode hook: tab-width=%d c-basic-offset=%d" tab-width c-basic-offset))
(add-hook 'c-mode-common-hook 'vg-tune-c)
 (add-hook 'js-mode-hook 'vg-tune-c)

(defun my-javascript-mode-hook ()
  (setq indent-tabs-mode t tab-width 4 js-indent-level 4)
  (modify-syntax-entry ?` "\"")
  (vg-message "JS mode template strings enabled"))
(add-hook 'js-mode-hook 'my-javascript-mode-hook)

(defun vg-tune-py ()
  (setq
   indent-tabs-mode t
   py-indent-tabs-mode t
   tab-width 2
   python-indent-offset 2)
 (vg-message "python-indent-offset=%d" python-indent-offset))
(add-hook 'python-mode-hook 'vg-tune-py)

(add-hook 'find-file-hook 'vg-open-file-hook)
(defun vg-open-file-hook (&rest _)
 (highlight-regexp "[[:nonascii:]]")
 (when
  (string-match
   "\\(py\\|cpp\\|h\\|_txt\\|Makefile\\|Kconfig\\)$" buffer-file-name)
  (compact-blame-mode)))

(defun tune-dabbrev ()
 (Vg-classify-as-punctuation "/"))

(add-hook 'sh-mode-hook 'tune-dabbrev)
(add-hook 'shell-mode-hook 'tune-dabbrev)
(add-hook 'makefile-mode-hook 'tune-dabbrev)
(defun vg-tune-org-mode ()
 (Vg-classify-as-punctuation "+$/'|")
 (define-key org-mode-map (kbd "ESC <up>")
  (define-key org-mode-map (kbd "ESC <down>")
   (lambda () (interactive)
	(vg-message "Move paragraph keys disabled"))))
 ;; These don't get message to not shadow the global-map bindings
 (define-key org-mode-map [C-tab] nil)
 (define-key org-mode-map [M-up] nil)
 (define-key org-mode-map [M-down] nil)
 (define-key org-mode-map [S-up] nil)
 (define-key org-mode-map [S-down] nil)
 (define-key org-mode-map (kbd "C-,") nil)
 (auto-fill-mode 1)
 (setq-local case-fold-search t)
 (setq-local compile-command
  (concat "/scripts/tasks.py "
   (file-name-nondirectory (buffer-file-name))))
 (push compile-command compile-history))
(add-hook 'org-mode-hook 'vg-tune-org-mode)

(defun vg-fill-lines-to-end ()
 (interactive)
 (save-excursion
  (while (not (eobp))
   (end-of-line)
   (do-auto-fill)
   (forward-line 1))))

(defun Vg-classify-as-punctuation (chars)
 (let* ((before "")
		(after (concat (mapcar
						(lambda (c)
						 (setq before (concat before
									   (string (char-syntax c))))
						 (modify-syntax-entry c ".")
						 (char-syntax c)) chars))))
  (vg-message "Char classes '%s' = '%s' -> '%s'" chars before after)))

(setq Vg-url-pattern "\\w+://\\([^\s\n\"]+\\)")
(defun Vg-tune-compilation (proc)
 "this is for grep to stop without confirmation when
 next grep is started"
 (set-process-query-on-exit-flag proc nil)
 (setq compilation-scroll-output
  (not (string-match "/tasks.py" (format "%s" (process-command proc)))))
 ;; get characters out of "symbol" class
 (Vg-classify-as-punctuation "-<>/&")
 (define-key compilation-mode-map "o" 'vg-open-url-desktop)
 (define-key compilation-mode-map "l" 'vg-load-url-editor)
 (define-key compilation-mode-map "f" 'vg-firefox-url)
 (define-key compilation-mode-map "e" 'vg-open-url-evince)
 (define-key compilation-mode-map [delete] 'kill-compilation)
 (define-key compilation-mode-map [kp-delete] 'kill-compilation)
 (highlight-regexp Vg-url-pattern)
 ;; Highlight debug print
 (highlight-regexp "\\bvg:.*$" 'hi-green))
(add-hook 'compilation-start-hook 'Vg-tune-compilation)

(require 'compile)
(add-to-list 'compilation-error-regexp-alist-alist
;; sub1 = file, sub2 = line, no column, type = warning
 '(asan " \\(/[^:\n]+\\):\\([0-9]+\\)" 1 2 nil 1))
(add-to-list 'compilation-error-regexp-alist 'asan)
(add-to-list 'compilation-error-regexp-alist-alist
 '(node "(\\(/[^:\n]+\\):\\([0-9]+\\)" 1 2))
(add-to-list 'compilation-error-regexp-alist 'node)
(add-to-list 'compilation-error-regexp-alist-alist
 '(meson1 "found at \\(/.+\\)" 1))
(add-to-list 'compilation-error-regexp-alist 'meson1)
(add-to-list 'compilation-error-regexp-alist-alist
 '(make "[[]\\([^:\n]+\\):\\([0-9]+\\):" 1 2))
(add-to-list 'compilation-error-regexp-alist 'make)

(defun Vg-get-local-search-command (query)
 ;; Need an interface for Spotlight search because the Finder one is no good.
 ;; It doesn't tell if it's done or still going, and it's always jumping.
 ;; Of course an additional good thing is ability to isearch results...
 (if (equal window-system 'ns)
  (format
   "mdfind %s"
   (replace-regexp-in-string "\"\\(.+?\\)\"" "'\"\\1\"'" 
	query))
  (format
   "tracker search --limit=999 --disable-color %s" query)))


(defun tracker-search () (interactive)
 (Vg-reset-dialog 'tracker-search)
 (Vg-start-local-search
  (read-shell-command "Command: "
   (Vg-get-local-search-command
	(Vg-current-word-or-selection)))))

(defun Vg-start-local-search (cmd)
 ;; Won't run if cwd is deleted
 (let* ((default-directory "/"))
  (with-current-buffer
   (compilation-start cmd 'compilation-mode
	(lambda (&rest _) "*tracker-search*"))
   (let* ((query (replace-regexp-in-string
				  (Vg-get-local-search-command "") "" cmd))
		  (noquotes-query (string-trim query "[\"']+" "[\"']+")))
	;; TODO Still doesn't work when buffer reverted
	(setq-local revert-buffer-function
	 (lambda (&rest _)
	  (setq-local compilation-finish-functions
	   (cons
		(lambda (b result)
		 (insert "\nSearch URLs:\n\n")
		 (Vg-ins-search-url "s" query
		  "https://www.google.com/search?q=%s")
		 (Vg-ins-search-url "u"
		  (concat query " -\"hey delphi\" -\"Roel Van de Paar\"")
		  "https://www.youtube.com/results?search_query=%s")
		 (Vg-ins-search-url "h" noquotes-query
		  "https://github.com/search?q=%s&type=code")
		 (Vg-ins-search-url "p" noquotes-query
		  "https://pkgs.org/search/?q=%s")
		 (Vg-ins-search-url "n" noquotes-query
		  "https://packages.ubuntu.com/search?keywords=%s")
		 (pop-to-buffer (current-buffer)))
		compilation-finish-functions))))
	(funcall revert-buffer-function)))))

(defun Vg-ins-search-url (key query template)
 (let ((url (format template (url-hexify-string query))))
  (insert (format "[%s] %s\n" key url))
  (define-key compilation-mode-map key
   (lambda () (interactive) (vg-open url)))))

(defun vg-local-search () (interactive)
 (Vg-start-local-search
  (Vg-get-local-search-command
   (if (use-region-p) (Vg-current-word-or-selection)
	(Vg-get-query-from-current-line)))))
(define-key global-map (kbd "s-9") 'vg-local-search)
 
(defmacro Vg-open-url (&rest body)
 `(let* ((line (thing-at-point 'line t))
		 (url
		  (if (string-match Vg-url-pattern line)
		   (match-string 0 line)
		   ;; Not an url but absolute path - also need that for
		   ;; mdfind output
		   (if (string-match "^/" line)
			(string-trim line)))))
   (if url
	(progn ,@body)
	(message "No url on current line"))))

(defun vg-open-url-desktop () (interactive)
 (Vg-open-url (vg-open url)))

(defun vg-load-url-editor () (interactive)
 (let* ((cmd (car compilation-arguments))
		(noquotes (replace-regexp-in-string "[\"']" "" cmd))
		(m (string-match "[^[:space:]]+$" noquotes))
		(str (match-string 0 noquotes)))
  (if m
   (Vg-open-url
	(find-file (if (string-match "^/" url) url
				(url-unhex-string (match-string 1 line))))
	(isearch-resume str nil t t str t))
   (vg-message "Search string not found"))))
 
 
(defun vg-open-url-evince () (interactive)
 (Vg-open-url
  (forward-line)
  (let* ((path (url-unhex-string (match-string 1 line)))
		 (snip (string-trim (thing-at-point 'line t)))
		 (word (nth 3 (string-split snip))))
   (Vg-start-process "evince" path "--find" word))))

(defun vg-firefox-url () (interactive)
 (Vg-open-url
  (Vg-start-process "/Applications/Firefox.app/Contents/MacOS/firefox" url)))

(defun vg-tune-log-view ()
  (vg-message "truncate-lines=%s" (setq truncate-lines nil)))
(add-hook 'log-view-mode-hook 'vg-tune-log-view)

(defun vg-tune-lisp ()
  (Vg-classify-as-punctuation "@/:|"))
(add-hook 'emacs-lisp-mode-hook 'vg-tune-lisp)
(add-hook 'tcl-mode-hook 'vg-tune-lisp)

(defun vg-file-open ()
 (highlight-regexp "[[:nonascii:]]"))
(add-hook 'find-file-hook 'vg-file-open)

; Set file types.
(add-to-list 'auto-mode-alist '("\\.ks\\'" . javascript-mode))
(add-to-list 'auto-mode-alist '("\\.cs\\'" . java-mode))
(add-to-list 'auto-mode-alist '("\\.h\\'" . c++-mode))
(add-to-list 'auto-mode-alist '("\\.js\\'" . javascript-mode))
(add-to-list 'auto-mode-alist '("\\.gyp\\'". javascript-mode))
(add-to-list 'auto-mode-alist '("\\.d\\'" . awk-mode))
(add-to-list 'auto-mode-alist '("Makefile" . makefile-mode))
(add-to-list 'auto-mode-alist '("\\.md\\.txt\\'" . markdown-mode))
(make-face-bold 'font-lock-keyword-face)
(make-face-italic 'font-lock-string-face)
(which-function-mode 1)


(defun utf () "Reload this buffer as utf-8" (interactive) 
  (let ((coding-system-for-read 'utf-8))
    (revert-buffer nil t t)))

(defun dos () "Reload this buffer as dos linebreaked text" (interactive) 
  (let ((coding-system-for-read 'windows-1251-dos))
    (revert-buffer nil t t)))

(defun wb () "White on black" (interactive)
  (set-background-color "black")
  (set-foreground-color "white"))

(defun bw () "Black on white" (interactive) 
  (set-background-color "white")
  (set-foreground-color "black"))

(defun git-log (options) "Print log with options"
 (interactive "sGit log options: ")
 (let* ((bn "*git-log*") proc
		(cmd (append
			  (if (equal window-system 'x)
			   '("systemd-inhibit" "--what=handle-lid-switch"))
			  '("git" "log") (split-string options))))
  (require 'vc-git)
  ;; TODO Need new buffer bc old CWD remains 
  (set-buffer (get-buffer-create bn))
  (setq-local revert-buffer-function
   (lambda (&rest ignored)
	(setq buffer-read-only nil)
	(erase-buffer)
	(setq vc-log-view-type 'long log-view-vc-backend 'git)
	(insert (format "--- Running %s...\n" cmd))
	(setq proc (apply 'start-process bn (current-buffer) cmd))
	(vc-git-log-view-mode) ;; <- This sets buffer-read-only
	(goto-char 1)
	(pop-to-buffer bn)))
  (funcall revert-buffer-function)))
 
;; This one is originally from https://zck.org/emacs-move-file
(defun move-file (new-location)
 "Write this file to NEW-LOCATION, and delete the old one."
 (interactive
  (list (expand-file-name
		 (if buffer-file-name
		  (read-file-name "Move file to: " default-directory
		   buffer-file-name nil
		   (file-name-nondirectory buffer-file-name))
		  (read-file-name "Move file to: "
		   default-directory
		   (expand-file-name (file-name-nondirectory (buffer-name))
			default-directory))))))
 ;; Add `mv` command semantics
 (when (file-directory-p new-location)
  (setq new-location
   (expand-file-name (file-name-nondirectory buffer-file-name)
	new-location)))
 (when (file-exists-p new-location)
  (delete-file new-location))
 (let ((old-location (expand-file-name (buffer-file-name))))
  (message "old file is %s and new file is %s"
   old-location
   new-location)
  (write-file new-location t)
  (when (and old-location
		 (file-exists-p new-location)
		 (not (string-equal old-location new-location)))
   (delete-file old-location))))

;; These are from https://www.emacswiki.org/emacs/MoveText
(defun move-text-internal (arg)
  (cond
   ((and mark-active transient-mark-mode)
    (if (> (point) (mark))
        (exchange-point-and-mark))
    (let ((column (current-column))
          (text (delete-and-extract-region (point) (mark))))
      (forward-line arg)
      (move-to-column column t)
      (set-mark (point))
      (insert text)
      (exchange-point-and-mark)
      (setq deactivate-mark nil)))
   (t
    (let ((column (current-column)))
      (beginning-of-line)
      (when (or (> arg 0) (not (bobp)))
        (forward-line)
        (when (or (< arg 0) (not (eobp)))
          (transpose-lines arg)
          (when (and nil (eval-when-compile
                       '(and (>= emacs-major-version 24)
                             (>= emacs-minor-version 3)))
                     (< arg 0))
            (vg-message "F=%s" (forward-line -1))))
        (forward-line -1))
      (move-to-column column t)))))

(defun move-text-down (arg)
  "Move region (transient-mark-mode active) or current line
  arg lines down."
  (interactive "*p")
  (move-text-internal arg))

(defun move-text-up (arg)
  "Move region (transient-mark-mode active) or current line
  arg lines up."
  (interactive "*p")				 
 (move-text-internal (- arg)))

(defun Vg-reset-dialog (cmd)
 "Experimental: replace active user input prompt (if any) with ours"
 (when (minibuffer-prompt)
  (run-at-time nil nil cmd)
  (throw 'exit t)))
									 
(defun gg ()
 "Start grep in the directory where the last grep was done"
 (interactive)
 (Vg-reset-dialog 'gg)
 (switch-to-buffer "*grep*")
 (command-execute 'grep))

;; That doesn't cancel user input request
;; (signal 'quit nil)

(defun Vg-get-current-line-escaped ()
 (beginning-of-line)
 ;; b-s-n-p and (point) go from 1, so (buffer-size) won't work here
 ;; (see Help for point-max for confirmation)
 (let ((cc (buffer-substring-no-properties (point) (point-max))))
  (string-match ".*[^\\\\]$" cc) ;; find 1st line without \
  ;; replace '\'s
  (replace-regexp-in-string "\\\\?\n" ""
   (substring cc 0 (match-end 0)))))
;; (format "cc='%s' p=%s s=%s end=%s" cc (point) (buffer-size) (match-end 0)))))

(defun vg-run-line () (interactive)
 (setq compile-command
  (string-trim
   (if (use-region-p)
	(buffer-substring-no-properties (region-beginning) (region-end))
	(Vg-get-current-line-escaped))))
 (condition-case err
  (save-buffer)
  (error (vg-message (error-message-string err))))
 (command-execute 'compile))

(defun g1 () "Show last commit" (interactive)
 (Compact-blame-show-commit "HEAD"))

(defun g0 () "Show not committed changes" (interactive)
 (save-some-buffers)
 (Compact-blame-show-commit "0000000000000000000000000000000000000000"))

(defun lm (path) "Load man page from file"
 (interactive "fPath to man page: ")
 (man (format "-l %s" path)))

(setq tramp-mode t)

(defalias 'afm 'auto-fill-mode)
(defalias 'yes-or-no-p 'y-or-n-p)
(defalias 'c 'compile)
(defalias 'bc 'emacs-lisp-byte-compile-and-load)
(defalias 'cbm 'compact-blame-mode)
(defalias 'gl 'git-log)
(defalias 'vcprl 'vc-print-root-log)
(defalias 'elbc+l 'emacs-lisp-byte-compile-and-load)
(defun vtt (path local)
 (interactive
  (let ((default-tag-dir
         (or (locate-dominating-file default-directory "TAGS.bz2")
          default-directory)))
   (list (read-file-name
          (format "Visit tags table, current='%s': "
		   tags-file-name)
          default-tag-dir
          (expand-file-name "TAGS.bz2" default-tag-dir) t)
    current-prefix-arg)))
 (require 'etags)
 (tags-reset-tags-tables)
 (visit-tags-table path local))

(setq compile-command "systemd-inhibit --what=handle-lid-switch\
 ionice -c3 scl enable gcc-toolset-13 -- make -k")
(setq compile-history (list compile-command))
(savehist-mode)

(server-start)
(setenv "EDITOR"
 (replace-regexp-in-string "/bin/bin/" "/bin/"
  (if (string-match "/src/" invocation-directory)
   (expand-file-name "../lib-src/emacsclient" invocation-directory)
   (expand-file-name "bin/emacsclient" invocation-directory))))
(setenv "PAGER" "cat")
(setenv "PATH"
 "/Library/Frameworks/Python.framework/Versions/3.10/bin:/usr/local/bin:$PATH" t)
(setenv "GCC_COLORS" "")
(setq shell-command-switch "-ic") ;; Load aliases in .bashrc
(setq process-connection-type nil)  ;; No pty
;; ^^ This lets us run sudo with interactive
(setenv "SUDO_ASKPASS" "/usr/libexec/openssh/gnome-ssh-askpass")
(setq-default case-fold-search nil case-replace nil
			  dabbrev-case-fold-search nil)
(setq revert-without-query '(".*"))
(setq create-lockfiles nil)
(setq perl-indent-level (setq cperl-indent-level 2))
(setq dired-listing-switches "-alh")
(setq ring-bell-function 'ignore)
(setq org-support-shift-select t)
(setq-default org-startup-truncated nil)
(setq-default org-startup-folded t)
(setq vc-command-messages t)
(setq visible-bell t)
(fringe-mode 0)
(add-hook 'after-save-hook 'executable-make-buffer-file-executable-if-script-p)
(defun vg-before-save ()
 (when (string-match "[.]yml$" buffer-file-name)
  (untabify 0 (point-max))
  (vg-message "Untabified %s" buffer-file-name)))
(add-hook 'before-save-hook 'vg-before-save)

;; remove git info from mode line
(defun vc-refresh-state () "Disable"
 (vg-message "vc-refresh-state disabled"))
(defun vc-before-save () "Disable"
 (vg-message "vc-before-save disabled"))
(defun vc-after-save () "Disable"
 (vg-message "Wrote %s (vc-after-save disabled) %d characters" buffer-file-name (buffer-size)))
(setq fast-but-imprecise-scrolling t)
(require 'grep)
(grep-apply-setting 'grep-command "git grep --recurse-submodules -En ")
(grep-apply-setting 'grep-use-null-device nil)
(setq sh-basic-offset 2)
(setq compilation-skip-threshold 2)
(setq recentf-max-saved-items 1024)
(menu-bar-mode -1)
(split-window-right)
(recentf-open-files)
(vg-message
 "Path='%s' tab-width=%s" load-file-name tab-width)
