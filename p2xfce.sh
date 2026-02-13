#!/bin/bash -e
# Configure and run XFCE session on a GPD Pocket 2
sudo mkdir -p /etc/X11/rotate
cat << END | sudo tee /etc/X11/rotate/monitor.conf
# GPD Pocket2 (modesetting)
Section "Monitor"
  Identifier "eDP-1"
  Option     "Rotate"  "right"
EndSection

# GPD Pocket2 (xorg-video-intel)
Section "Monitor"
  Identifier "eDP1"
  Option     "Rotate"  "right"
EndSection

Section "InputClass"
  Identifier     "GPD Pocket 2 trackpoint"
  MatchProduct   "HAILUCK CO.,LTD USB KEYBOARD Mouse"
  MatchIsPointer "on"
  Driver         "libinput"
  Option         "MiddleEmulation" "1"
  Option         "ScrollButton"    "3"
  Option         "ScrollMethod"    "button"
EndSection
END
mkdir -p ~/.xfce4
# TODO: xrandr here doesn't do anything (only works from terminal)
cat << END | tee ~/.xfce4/p2xinitrc
#!/bin/bash
xrandr --output eDP1 --scale 0.64x0.64 ||\
xrandr --output eDP-1 --scale 0.64x0.64
xinput set-prop "pointer:Goodix Capacitive TouchScreen" --type=float\
 "Coordinate Transformation Matrix" 0 1 0 -1 0 1 0 0 1
xset s off
exec /etc/xdg/xfce4/xinitrc
END

set -xe
export MOZ_USE_XINPUT2=1
chmod +x ~/.xfce4/p2xinitrc
exec xinit ~/.xfce4/p2xinitrc -- vt$XDG_VTNR -configdir rotate
