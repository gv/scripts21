;; Eval before cursor is C-x C-e -*-lexical-binding: t-*-

(message "Trying to load init.el by vg...")
(setq force-load-messages t)

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

(global-set-key [home] 'beginning-of-line)
(global-set-key [end] 'end-of-line)
; Workaround for windows remote terminals
(global-set-key [select] 'end-of-line)
(global-set-key [\C-home] 'beginning-of-buffer)
(global-set-key [\C-end] 'end-of-buffer)
(global-set-key [(control y)] 
  '(lambda () 
     (interactive)
     (beginning-of-line)
     (kill-line)))
;; setting some f[1-12] keys
(global-set-key [f2]    'save-buffer)
(global-set-key [M-f4]  'save-buffers-kill-emacs)
(global-set-key [C-f]  'isearch-forward)
(global-set-key [M-f7]  'find-name-dired)
(global-set-key [C-tab]  'other-window)

(global-set-key [A-end] 'end-of-buffer)
(global-set-key [A-home] 'beginning-of-buffer)
(global-set-key (kbd "A-k") 'kill-line)
(global-set-key (kbd "A-/") 'dabbrev-expand)
(global-set-key (kbd "A-'") 'other-window)
;;(global-set-key [C-x] 'clipboard-kill-region)
(global-set-key (kbd "C-v") 'cua-paste)
(global-set-key [M-tab] 'other-window)
;(load "../ltags/ties/question")
;(global-set-key [M-up] 'question-here)
;(global-set-key (kbd "ESC <up>") 'question-here)
(global-set-key [M-up] 'previous-error)
(global-set-key (kbd "ESC <up>") 'previous-error)
(global-set-key [M-down] 'next-error)
;(global-set-key [M-.] 'question-eponimous)
(global-set-key (kbd "C-p") 'dabbrev-expand)
(global-set-key (kbd "C-/") 'dabbrev-expand)
(global-set-key [A-M-down] 'ft-at-point)
(global-set-key [A-M-S-down] 'ft-other-window-at-point)
(global-set-key [A-C-M-down] 'ft-other-window-at-point)
(global-set-key [A-M-next] 'ft-other-window-at-point)
(global-set-key [A-M-up] 'pop-tag-mark)
; [A-M-/] didn't work
(global-set-key (kbd "A-M-/") 'ft-next)

(when (fboundp 'osx-key-mode)
  (define-key osx-key-mode-map [(end)] 'end-of-line)
  (define-key osx-key-mode-map [(home)] 'beginning-of-line)
  (define-key osx-key-mode-map [M-up] 'backward-paragraph)
  (define-key osx-key-mode-map [M-down] 'forward-paragraph)
  (define-key osx-key-mode-map `[(,osxkeys-command-key up)] 'previous-error)
  (define-key osx-key-mode-map `[(,osxkeys-command-key down)] 'next-error)
  (define-key osx-key-mode-map `[(meta z)] 'aquamacs-undo)
  (define-key osx-key-mode-map `[(meta c)] 'clipboard-kill-ring-save)
  (define-key osx-key-mode-map `[(meta v)] 'cua-paste)
  (define-key osx-key-mode-map `[(,osxkeys-command-key i)] 'test)
  (define-key osx-key-mode-map (kbd "A-;")
	(lambda () (interactive) (message "Spell check disabled")))
  ;; latvian keyboard workaround 
  (define-key osx-key-mode-map (kbd "M-'")
	(lambda () (interactive) (insert "`")))
  )

(when (and (not (fboundp 'osx-key-mode)) (equal window-system 'ns))
 (define-key global-map (kbd "s-[") 'backward-sexp)
 (define-key global-map (kbd "s-]") 'forward-sexp)
  (define-key global-map [M-up] 'backward-paragraph)
  (define-key global-map [M-down] 'forward-paragraph)
  (define-key global-map [s-home] 'beginning-of-buffer)
  (define-key global-map [s-end] 'end-of-buffer)
  (define-key global-map [s-up] 'previous-error)
  (define-key global-map [s-down] 'next-error)
  (define-key global-map [M-s-up] 'pop-tag-mark)
  (define-key global-map [M-s-down] 'ft-at-point)
  (define-key global-map [C-M-s-down] 'ft-other-window-at-point)
  (define-key global-map [M-s-right] 'ft-other-window-at-point)
  (define-key global-map (kbd "M-s-÷") 'ft-next)
  ;; [s-\`] [s-/] do not work!
  (define-key global-map (kbd "s-/") 'dabbrev-expand)
  (define-key global-map (kbd "s-`") 'next-multiframe-window)
  (define-key global-map (kbd "C-\\")
	(lambda () (interactive) (message "Keyboard language switch disabled")))
  ;; latvian keyboard workaround 
  (define-key global-map (kbd "M-'")
	(lambda () (interactive) (insert "`")))
  (let ((size 10) (i 0) name
		(fonts ["Menlo" "Courier" "Monaco" "PT Mono" "Andale Mono"]))
	(defun vg-update-font (ns ni)
	  (setq size ns i (% ni (length fonts)))
	  (setq name (format "%s-%d" (aref fonts i) size))
	  (set-frame-font name t)
	  (message "Font: %s" name))
	(define-key global-map (kbd "s-=")
	  (lambda () (interactive) (vg-update-font (+ 1 size) i)))
	(define-key global-map (kbd "s--")
	  (lambda () (interactive) (vg-update-font (- size 1) i)))
	(define-key global-map (kbd "s-0")
	  (lambda () (interactive) (vg-update-font size (1+ i))))
	(vg-update-font size i)))

(defun ft-at-point () "AKA go to def" (interactive)
	   (find-tag (find-tag-default)))

(defun ft-next () "Other def" (interactive)
	   (find-tag () t))

(defun ft-other-window-at-point () "Set other window to def" (interactive)
	   (find-tag-other-window (find-tag-default)))
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
(if (equal window-system 'x)
	;; "Bitstream Vera Sans Mono-9"
	(set-default-font "Monospace-9"))
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
(prefer-coding-system 'koi8-r-dos)
(prefer-coding-system 'cp866-dos)
(prefer-coding-system 'windows-1251-dos)
(prefer-coding-system 'utf-8-unix)

;; 
;;     PROGRAMMING
;;     ```````````
;;

; Загрузим другие программы 
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
  (setq compact-blame-bg2 "rainbow"))

;; for ViewSourceWith Firefox extension
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
  (abbrev-mode -1)
  (message
   "C mode hook: tab-width=%d c-basic-offset=%d" tab-width c-basic-offset))
(add-hook 'c-mode-common-hook 'vg-tune-c)
(add-hook 'js-mode-hook 'vg-tune-c)

(defun my-javascript-mode-hook ()
  (setq indent-tabs-mode t tab-width 4 js-indent-level 4)
  (modify-syntax-entry ?` "\"")
  (message "JS mode template strings enabled")
  )
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

(defun tune-dabbrev ()
  (modify-syntax-entry ?/ ".")
  (message "Char syntax: /=%s" (string (char-syntax ?/)))
  ;;(set (make-local-variable 'dabbrev-abbrev-char-regexp) "[A-Za-z0-9_]")
  ;;(message "dabbrev-abbrev-char-regexp set to '%s'" dabbrev-abbrev-char-regexp)
  )

(add-hook 'sh-mode-hook 'tune-dabbrev)
(add-hook 'shell-mode-hook 'tune-dabbrev)
(add-hook 'org-mode-hook 'tune-dabbrev)
(add-hook 'makefile-mode-hook 'tune-dabbrev)
(defun vg-tune-org-mode ()
  (auto-fill-mode 1))
(add-hook 'org-mode-hook 'vg-tune-org-mode)

(defun vg-tune-compilation (procname)
  "this is for grep to stop without confirmation when 
next grep is started"
  (set-process-query-on-exit-flag
   (get-buffer-process (current-buffer)) nil)
  ;; get '-' character out of "symbol" class
  (modify-syntax-entry ?- ".")
  (message "Char classes:-=%s" (string (char-syntax ?-))))
(add-hook 'compilation-start-hook 'vg-tune-compilation)

(defun vg-tune-log-view ()
  (message "truncate-lines=%s" (setq truncate-lines nil)))
(add-hook 'log-view-mode-hook 'vg-tune-log-view)

(defun vg-tune-lisp ()
  (modify-syntax-entry ?@ ".")
  (message "Char classes:@=%s" (string (char-syntax ?@))))
(add-hook 'emacs-lisp-mode-hook 'vg-tune-lisp)

(defun vg-after-save ()
  (when (and
		 (string-equal mode-name "Emacs-Lisp")
		 (not
		  (string-match "/shoe.el$" buffer-file-name)))
	(message "Saved %s & evaluating..." buffer-file-name)
	(eval-buffer)))
(add-hook 'after-save-hook 'vg-after-save)

(if window-system
	(global-set-key (kbd "M-[") 'gtags-find-rtag)
)

; Set file types.
(add-to-list 'auto-mode-alist '("\\.ks\\'" . javascript-mode))
(add-to-list 'auto-mode-alist '("\\.cs\\'" . java-mode))
(add-to-list 'auto-mode-alist '("\\.h\\'" . c++-mode))
(add-to-list 'auto-mode-alist '("\\.js\\'" . javascript-mode))
(add-to-list 'auto-mode-alist '("\\.gyp\\'". javascript-mode))
(add-to-list 'auto-mode-alist '("\\.d\\'" . awk-mode))
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

(defun git-log (options)
  "Print log with options"
  (interactive "sGit log options: ")
  (let ((bn "*git-log*"))
	(set-buffer (get-buffer-create bn))
	(vc-setup-buffer bn)
	;;(let ((inhibit-read-only t))
	;; (with-current-buffer bn
	(apply 'vc-git-command bn 'async nil "log" (split-string options))
	;;	))
	(setq vc-log-view-type 'long log-view-vc-backend 'git)
	(vc-git-log-view-mode)
	(setq buffer-read-only t)
	;; [ ] add message to buffer when process is done; use "compile"
	;;     or vc-run-delayed
	(pop-to-buffer bn)))

(setq tramp-mode nil)

(defalias 'yes-or-no-p 'y-or-n-p)
(defalias 'c 'compile)
(defalias 'cbm 'compact-blame-mode)
(defalias 'gl 'git-log)
(defun vtt () (interactive)
	   (require 'etags)
	   (tags-reset-tags-tables)
	   (command-execute 'visit-tags-table))

(server-start)
(setenv
 "EDITOR" "/Volumes/aux_apps/Emacs.app/Contents/MacOS/bin/emacsclient")
(setenv "GREP_OPTIONS" "--recursive --binary-files=without-match")
(setenv "PAGER" "cat")
(setq-default case-fold-search nil case-replace nil
			  dabbrev-case-fold-search nil)
(setq revert-without-query '(".*"))
(setq create-lockfiles nil)
(setq cperl-indent-level 2)
(setq dired-listing-switches "-alh")
(setq ring-bell-function 'ignore)
(setq org-support-shift-select t)
(setq-default org-startup-truncated nil)
(setq vc-command-messages t)
(setq visible-bell t)
(fringe-mode 0)
(add-hook 'after-save-hook 'executable-make-buffer-file-executable-if-script-p)
;; remove git info from mode line
(defun vc-refresh-state () "Disable"
	   (message "vc-refresh-state disabled"))
(defun vc-after-save () "Disable"
	   (message "vc-after-save disabled"))
(setq fast-but-imprecise-scrolling t)

(message "tab-width=%s case-fold-search=%s" tab-width case-fold-search)

