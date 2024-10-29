;; ____________________________________________________________________________
;; Aquamacs custom-file warning:
;; Warning: After loading this .emacs file, Aquamacs will also load
;; customizations from `custom-file' (customizations.el). Any settings there
;; will override those made here.
;; Consider moving your startup settings to the Preferences.el file, which
;; is loaded after `custom-file':
;; ~/Library/Preferences/Aquamacs Emacs/Preferences
;; _____________________________________________________________________________
(setq load-path (cons "~/stuff/elisp" load-path))
(load "~/stuff/elisp/shoe.el")

(custom-set-variables
 ;; custom-set-variables was added by Custom.
 ;; If you edit it by hand, you could mess it up, so be careful.
 ;; Your init file should contain only one such instance.
 ;; If there is more than one, they won't work right.
 '(safe-local-variable-values
   (quote
	((vg-codeql-module-root . "/win/kserver")
	 (compact-blame-future-warning-branch . "origin/releases/6.4.4")
	 (js-indent-level . 2)
	 (vc-default-patch-addressee . "bug-gnu-emacs@gnu.org")
	 (etags-regen-ignores "test/manual/etags/")
	 (etags-regen-regexp-alist
	  (("c" "objc")
	   "/[ 	]*DEFVAR_[A-Z_ 	(]+\"\\([^\"]+\\)\"/\\1/" "/[ 	]*DEFVAR_[A-Z_ 	(]+\"[^\"]+\",[ 	]\\([A-Za-z0-9_]+\\)/\\1/"))
	 (vc-prepare-patches-separately)
	 (diff-add-log-use-relative-names . t)
	 (vc-git-annotate-switches . "-w")
	 (perl-continued-statement . 2))))
 '(send-mail-function (quote mailclient-send-it)))
(custom-set-faces
 ;; custom-set-faces was added by Custom.
 ;; If you edit it by hand, you could mess it up, so be careful.
 ;; Your init file should contain only one such instance.
 ;; If there is more than one, they won't work right.
 )
