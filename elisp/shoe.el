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
(global-set-key [(control y)] 
 '(lambda () (interactive)
   (beginning-of-line)
   (kill-line)))
(global-set-key (kbd "A-k") 'kill-line)
(define-key global-map (kbd "C-a") 'mark-whole-buffer)
(define-key global-map (kbd "s-a") 'mark-whole-buffer)
;; [C-f] didn't work
(define-key global-map (kbd "C-f") 'isearch-forward)
;; TODO Breaks all Alt key combinations
;; Trying to bind them throws:
;; "Key sequence ESC ESC starts with non-prefix key ESC"
;; (define-key global-map (kbd "ESC") 'keyboard-quit)
(define-key global-map (kbd "ESC ESC") 'keyboard-quit)
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
(define-key global-map (kbd "s-f") 'vg-insert-current-file-path)
(define-key global-map (kbd "C-\\")
 (lambda () (interactive)
  (vg-message "Keyboard language switch disabled")))
(define-key global-map (kbd "s-g") 'google-at-point)
(define-key global-map (kbd "s-b") 'google-line)
(define-key global-map (kbd "s-o") 'vg-line-2-tor-browser) 
;; Use with Shift on XFCE
(define-key global-map (kbd "s-r") 'revert-buffer)
(define-key global-map (kbd "s-k") 'kill-current-buffer)
(define-key global-map [C-backspace] 'vg-backward-delete-word)
(define-key global-map [M-backspace] 'vg-backward-delete-word)
;; Use a key from shell
(define-key global-map (kbd "C-w") 'vg-backward-delete-word)
(define-key global-map [s-left] 'previous-buffer)
(define-key global-map [s-right] 'next-buffer)
;; Norton Commander had Ctrl-U, but it's used for another thing,
;; and Flag-U does something else on Mac, so it's Alt-U for now
(define-key global-map (kbd "M-u") 'window-swap-states)
;; TODO mimic vscode
(define-key global-map (kbd "s-1") 'other-window)
(define-key global-map (kbd "s-2") 'other-window)
;; Go to the notes
(define-key global-map (kbd "s-3")
 (lambda () (interactive) (find-file "~/20note.org")))
(define-key global-map (kbd "s-4")
 (lambda () (interactive) (switch-to-buffer "*compilation*")))
;; TODO Set C-; to dabbrev expand? Bc its near space
(global-set-key [M-down] 'move-text-down)
(global-set-key [M-up] 'move-text-up)
;; Option:
;; (define-key global-map [s-delete]
;;  (lambda () (interactive) (just-one-space -1)))
(define-key global-map [s-delete]
 (lambda () (interactive) (cycle-spacing -1)))
(define-key global-map [s-kp-delete]
 (lambda () (interactive) (cycle-spacing -1)))
(define-key global-map (kbd "s-h") 'query-replace)
(define-key global-map (kbd "M-RET") 'dired-find-file-other-window)

(defun vg-trash-buffer-file () (interactive)
 ;; TODO
 (save-buffer)
 (if (with-current-buffer "*Messages*"
	  (let ((buffer-read-only nil))
	   (call-process "gio" nil t nil "trash" "TODO: confirm")))
  (vg-message "TODO")
  (kill-buffer)))
(define-key global-map [f8] 'vg-trash-buffer-file)

(defun vg-case-insensitive-isearch () (interactive)
 (let ((case-fold-search t))
  (command-execute 'isearch-forward)))
(define-key global-map (kbd "s-i") 'vg-case-insensitive-isearch)

;; Compile/grep
(define-key global-map (kbd "s-q") 'compile)
;; TODO `recompile` doesn't restore CWD of the last compile 
(define-key global-map (kbd "s-y") 'recompile)
(define-key global-map (kbd "s-s") 'gg)
(global-set-key (kbd "ESC <up>") 'previous-error)
(define-key global-map [s-up] 'previous-error)
(define-key global-map [s-down] 'next-error)
;; Mimic Cmd-F on Mac Finder
(define-key global-map (kbd "M-f") 'tracker-search)
(define-key global-map (kbd "s-l") 'vg-run-line)
(define-key global-map (kbd "C-l") 'vg-run-line)
(global-set-key [M-f7]  'find-name-dired)
(define-key global-map [f6] 'rename-buffer)

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

(defun vg-write+merge (dest) (interactive "fPath to write + merge:")
 ;; TODO: rewrite using a temp file instead of `git stash`
 (let ((sp (point)))
  (when (file-directory-p dest)
   (setq dest
	(expand-file-name (file-name-nondirectory buffer-file-name)
	 dest)))
  (if (not (file-exists-p new-location))
   (write-file dest)
   (let ((default-directory (file-name-nondirectory)))
	(Vg-with-cmd-output
	 (list "git" "stash" "push" "-m"
	  (format "Saving file '%s' for vg-write+merge" dest)
	  "--" dest)
	 (write-file dest)
	 (unless (string= output "No local changes to save")
	  (if
	   (string-match
		"and index state WIP on [^:]+: \\([0-9a-zA-Z]+\\)" output)
	   (Vg-with-cmd-output
		(list "git" "stash" "apply" (match-string 1 output)))
	   (vg-message "Unknown output from %s: %s" cmd output))
	  (revert-buffer)
	  (goto-char sp)))))))

(defun vg-line-2-tor-browser () (interactive)
 ;; TODO: Doesn't work, shows "running but not responding" msg
 (let ((url (thing-at-point 'line t)))
  (Vg-start-process "setsid" "nohup"
   (expand-file-name "~/alpha-tor-browser/Browser/firefox")
   "--detach" url)))

(defun vg-insert-current-file-path () (interactive)
 (insert
  (or (buffer-file-name (window-buffer (minibuffer-selected-window)))
   (buffer-name (window-buffer (minibuffer-selected-window))))))

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
 (if (use-region-p)
  (format "\"%s\"" (buffer-substring-no-properties
					(region-beginning) (region-end)))
  (find-tag-default)))

(defun google-at-point () (interactive)
 (let
  ((q (Vg-current-word-or-selection)))
  (Vg-open-browser (format "https://www.google.com/search?q=%s" q))))

(defun google-line () (interactive)
 (if (use-region-p)
  (google-at-point)
  (Vg-open-browser
   (format "https://www.google.com/search?q=%s"
	(replace-regexp-in-string "[[] []]\\|Q:" ""
	 (thing-at-point 'line))))))

(defun Vg-open-browser (url)
 (if (equal window-system 'ns)
  (vg-open url)
  (start-process url "*Messages*" "firefox" url)))

(defun vg-open (x)
 (let ((cmd (append (if (equal window-system 'ns) '("open")
					 '("setsid" "nohup" "xdg-open")) (list x))))
  (apply 'Vg-start-process cmd)))

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

;;Используем Windows 1251
;(set-language-environment "Russian")
;(define-coding-system-alias 'windows-1251 'cp1251)
;(set-buffer-file-coding-system 'windows-1251-dos)
;(set-default-coding-systems 'windows-1251-dos)
;(set-terminal-coding-system 'windows-1251-dos)
;(set-selection-coding-system 'windows-1251-dos)
;(set-clipboard-coding-system 'windows-1251-dos)
;;
;; Использовать окружение UTF-8
(set-language-environment 'UTF-8)
(set-buffer-file-coding-system 'utf-8-unix)
(set-default-coding-systems 'utf-8-unix)
(set-terminal-coding-system 'utf-8-dos)
(set-selection-coding-system 'utf-8-dos)
;;(prefer-coding-system 'koi8-r-dos)
;;(prefer-coding-system 'cp866-dos)
;;(prefer-coding-system 'windows-1251-dos)
;;(prefer-coding-system 'utf-8-unix)
(setq coding-system-for-read 'utf-8)

;; 
;;     PROGRAMMING
;;     ```````````
;;

; Here we rely on load path set in .emacs. TODO use path of this file
(autoload 'php-mode "php-mode.el" "XXX" t)
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
 (highlight-regexp ".xperience .*financial" 'hi-pink)
 (highlight-regexp ".xperience .*mbedded" 'hi-pink)
 (highlight-regexp ".xperience .*quant" 'hi-pink)
 (highlight-regexp ".xperience .*trading" 'hi-pink)
 (highlight-regexp ".xperience .*icrocontrollers" 'hi-pink)
 (highlight-regexp ".xperience .*ndroid" 'hi-pink)
 (highlight-regexp ".*mbedded.*xperience.*" 'hi-pink)
 (highlight-regexp ".*ow.latency.*xperience.*" 'hi-pink)
 (highlight-regexp ".itizen" 'hi-pink)
 (highlight-regexp ".*visa.*" 'hi-pink)
 (highlight-regexp "German\b" 'hi-pink) 
 (highlight-regexp "working rights" 'hi-pink)
 )

;; For Viewsourcewith Firefox extension
;;(add-to-list 'auto-mode-alist '("index.\\.*" . wikipedia-mode))

(defun vg-tune-c ()
  (setq c-basic-offset 4
		tab-width 4
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
   ;; c-basic-offset 2
   indent-tabs-mode t
   py-indent-tabs-mode t
   tab-width 4
   python-indent-offset 4
   ))
(add-hook 'python-mode-hook 'vg-tune-py)

(add-hook 'python-mode-hook 'compact-blame-mode)
(add-hook 'cperl-mode-hook 'compact-blame-mode)
(add-hook 'perl-mode-hook 'compact-blame-mode)
(add-hook 'c-mode-common-hook 'compact-blame-mode)
(add-hook 'makefile-mode-hook 'compact-blame-mode)
(add-hook 'js-mode-hook 'compact-blame-mode)
(add-hook 'tcl-mode-hook 'compact-blame-mode)
(add-hook 'bat-mode-hook 'compact-blame-mode)
(add-hook 'emacs-lisp-mode-hook 'compact-blame-mode)

(defun tune-dabbrev ()
 (Vg-classify-as-punctuation "/")
  ;;(set (make-local-variable 'dabbrev-abbrev-char-regexp) "[A-Za-z0-9_]")
  ;;(vg-message "dabbrev-abbrev-char-regexp set to '%s'" dabbrev-abbrev-char-regexp)
  )

(add-hook 'sh-mode-hook 'tune-dabbrev)
(add-hook 'shell-mode-hook 'tune-dabbrev)
(add-hook 'makefile-mode-hook 'tune-dabbrev)
(defun vg-tune-org-mode ()
 (tune-dabbrev)
 (Vg-classify-as-punctuation "+$")
 (define-key org-mode-map (kbd "ESC <up>")
  (define-key org-mode-map (kbd "ESC <down>")
   (lambda () (interactive)
	(vg-message "Move paragraph keys disabled"))))
 ;; These don't get message to not shadow the global-map bindings
 (define-key org-mode-map [C-tab] nil)
 (define-key org-mode-map [M-up] nil)
 (define-key org-mode-map [M-down] nil)
 (auto-fill-mode 1)
 (setq-local case-fold-search t)
 (setq-local compile-command
  (concat "/scripts/tasks.py "
   (file-name-nondirectory (buffer-file-name))))
 (push compile-command compile-history))
(add-hook 'org-mode-hook 'vg-tune-org-mode)

(defun Vg-classify-as-punctuation (chars)
 (let* ((before "")
		(after (concat (mapcar
						(lambda (c)
						 (setq before (concat before
									   (string (char-syntax c))))
						 (modify-syntax-entry c ".")
						 (char-syntax c)) chars))))
  (vg-message "Char classes '%s' = '%s' -> '%s'" chars before after)))

(setq Vg-url-pattern "\\w+://[^\s\n\"]+")
(defun Vg-tune-compilation (proc)
 "this is for grep to stop without confirmation when
 next grep is started"
 (set-process-query-on-exit-flag proc nil)
 (setq compilation-scroll-output
  (not (string-match "/tasks.py" (format "%s" (process-command proc)))))
 ;; get characters out of "symbol" class
 (Vg-classify-as-punctuation "-<>/")
 (define-key compilation-mode-map "o" 'vg-open-url)
 (define-key compilation-mode-map "f" 'vg-firefox-url)
 (highlight-regexp Vg-url-pattern)
 ;; Highlight debug print
 (highlight-regexp "vg:.*$" 'hi-green))
(add-hook 'compilation-start-hook 'Vg-tune-compilation)

(defun tracker-search () (interactive)
 (let ((cmd (read-shell-command "Command: "
			 (concat "tracker search --limit=999 --disable-color "
			  (Vg-current-word-or-selection)))))
  (compilation-start cmd 'compilation-mode
   (lambda (&rest _) "*tracker-search*"))))
 
(defun vg-open-url () (interactive)
 (let* ((line (thing-at-point 'line t))
		(url
		 (if (string-match Vg-url-pattern line)
		  (match-string 0 line))))
  (if url
   (vg-open url)
   (message "No url on current line"))))

(defun vg-tune-log-view ()
  (vg-message "truncate-lines=%s" (setq truncate-lines nil)))
(add-hook 'log-view-mode-hook 'vg-tune-log-view)

(defun vg-tune-lisp ()
  (Vg-classify-as-punctuation "@/"))
(add-hook 'emacs-lisp-mode-hook 'vg-tune-lisp)

(defun Vg-tune-tcl ()
 (Vg-classify-as-punctuation ":/"))
(add-hook 'tcl-mode-hook 'Vg-tune-tcl)

(defun vg-after-save ()
 (when
  (and (string-equal (format "%s" mode-name) "Emacs-Lisp")
   (not (string-match "/\\(shoe\\|.dir-locals\\).el$" buffer-file-name)))
  (vg-message "Saved %s & evaluating..." buffer-file-name)
  (eval-buffer)))
(add-hook 'after-save-hook 'vg-after-save)

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
	   (cmd (append '("git" "log") (split-string options))))
  (require 'vc-git)
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
									 
(defun gg ()
 "Start grep in the directory where the last grep was done"
 (interactive)
 ;; Experimental: replace active user input prompt (if any) with ours
 (when (minibuffer-prompt)
  (run-at-time nil nil 'gg)
  (throw 'exit t))
 (switch-to-buffer "*grep*")
 (command-execute 'grep))

;; That doesn't cancel user inpuut request
;; (signal 'quit nil)

(defun Vg-get-current-line-escaped ()
 (beginning-of-line)
 (let ((cc (buffer-substring-no-properties (point) (buffer-size))))
  (string-match ".*[^\\\\]$" cc)
  (replace-regexp-in-string "\\\\?\n" ""
   (substring cc 0 (match-end 0)))))

(defun vg-run-line () (interactive)
 (setq compile-command (Vg-get-current-line-escaped))
 (save-buffer)
 (command-execute 'compile))

(defun g1 () "Show last commit" (interactive)
 (Compact-blame-show-commit "HEAD"))
(defalias 'gh 'g1)

(defun g0 () "Show not committed changes" (interactive)
 (Compact-blame-show-commit "0000000000000000000000000000000000000000"))
(defalias 'gj 'g0)

(defun lm (path) "Load man page from file"
 (interactive "fPath to man page: ")
 (man (format "-l %s" path)))

(setq tramp-mode nil)

(defalias 'yes-or-no-p 'y-or-n-p)
(defalias 'c 'compile)
(defalias 'bc 'emacs-lisp-byte-compile-and-load)
(defalias 'cbm 'compact-blame-mode)
(defalias 'gl 'git-log)
(defalias 'vcprl 'vc-print-root-log)
(defun vtt () (interactive)
 (require 'etags)
 (tags-reset-tags-tables)
 (command-execute 'visit-tags-table))

(setq compile-command "systemd-inhibit --what=handle-lid-switch\
 ionice -c3 scl enable gcc-toolset-12 'make -k'")
(setq compile-history (list compile-command))
(savehist-mode)

(server-start)
(setenv "EDITOR"
 (replace-regexp-in-string "/bin/bin/" "/bin/"
  (if (string-match "/src/" invocation-directory)
   (expand-file-name "../lib-src/emacsclient" invocation-directory)
   (expand-file-name "bin/emacsclient" invocation-directory))))
(setenv "GREP_OPTIONS" "--binary-files=without-match")
(setenv "PAGER" "cat")
(setenv "PATH"
 "/Library/Frameworks/Python.framework/Versions/3.10/bin:$PATH" t)
(setenv "GCC_COLORS" "")
(setq process-connection-type nil)  ;; No pty
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
;; remove git info from mode line
(defun vc-refresh-state () "Disable"
	   (vg-message "vc-refresh-state disabled"))
(defun vc-after-save () "Disable"
	   (vg-message "Wrote %s (vc-after-save disabled)" buffer-file-name))
(setq fast-but-imprecise-scrolling t)
(require 'grep)
(grep-apply-setting 'grep-command "git grep --recurse-submodules -n ")
(grep-apply-setting 'grep-use-null-device nil)
(setq sh-basic-offset 2)
(setq compilation-skip-threshold 2)
(setq recentf-max-saved-items 1024)
(menu-bar-mode -1)
(split-window-right)
(recentf-open-files)
(vg-message
 "tab-width=%s case-fold-search=%s" tab-width case-fold-search)
