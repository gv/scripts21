#!/usr/bin/perl -w
# Run xterm with randomized color palette

@colors = ();
$i = 0;
while($i < 16) {
	$colors[$i] = sprintf("#%06X", int(rand(0x1000000)));
	$i++;
}

@colors = sort {
#	$aa = ord(substr($a, -2)) + ord(substr($a, -4)) + ord(substr($a, -6));
#	$bb = ord(substr($b, -2)) + ord(substr($b, -4)) + ord(substr($b, -6));

	$aa = hex(substr($a, -2)) + hex(substr($a, -4, 2)) + hex(substr($a, -6, 2));
	$bb = hex(substr($b, -2)) + hex(substr($b, -4, 2)) + hex(substr($b, -6, 2));
	return $aa <=> $bb;
} @colors;

$path = "temp-resources";
open(H, ">", $path)  || die "$0: can't open $path for writing: $!";

if(rand(2) > 1) {
	@colors = reverse @colors;
}

$i = 0;
while($i < 16) {
	$c = $colors[$i];

	print(H "xterm*color${i}: $c\n");
	if($i == 0) {
		print(H "xterm*background: $c\n");
	} elsif($i == 15) {
		print(H "xterm*foreground: $c\n");
	}
	$i++;
}

=pod
  XTerm Translations, i.e. keyboard remapping.

 Notes:
   ~       means that that modifier must not be asserted.
   !       means that the listed modifiers must be in the correct state and
               no other modifiers can be asserted.
   None    means no modifiers can be asserted.
   :       directs the Intrinsics to apply any standard modifiers in the event.
   ^       is an abbreviation for the Control modifier.
   $       is an abbreviation for Meta

 Example:
   No modifiers:                          None <event> detail
   Any modifiers:                              <event> detail
   Only these modifiers:           ! mod1 mod2 <event> detail
   These modifiers and any others:   mod1 mod2 <event> detail
=cut

print(H '
xterm*faceName:Liberation Mono:size=12:antialias=true
xterm*vt100*geometry: 80x30
xterm*selectToClipboard: true
! Only select text, not empty space around it.
xterm*highlightSelection: true
! Dont automatically jump to the bottom on output, but do on keypress.
XTerm*scrollTtyOutput:          false
XTerm*scrollKey:                true
XTerm*vt100.translations:   #override           \n\
  ! Ctrl <Key> =:          larger-vt-font()    \n\
  ! Ctrl <Key> -:          smaller-vt-font()   \n\

');
system("xrdb temp-resources");
exec("xterm", @ARGV);

