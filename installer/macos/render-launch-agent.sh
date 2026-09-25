#!/bin/sh
set -eu

[ "$#" -eq 5 ] || {
  echo "usage: $0 <wd-agent> <agent-config> <state-dir> <stdout-log> <stderr-log>" >&2
  exit 2
}

for path in "$@"; do
  case "$path" in
    /*) ;;
    *) echo "all launch agent paths must be absolute: $path" >&2; exit 1 ;;
  esac
  case "$path" in
    *'
'*) echo "launch agent paths must not contain newlines" >&2; exit 1 ;;
  esac
done

xml_escape() {
  LC_ALL=C awk 'BEGIN {
    s = ARGV[1]; ARGV[1] = "";
    gsub(/&/, "\\&amp;", s);
    gsub(/</, "\\&lt;", s);
    gsub(/>/, "\\&gt;", s);
    print s;
  }' "$1"
}

agent=$(xml_escape "$1")
config=$(xml_escape "$2")
state=$(xml_escape "$3")
stdout_log=$(xml_escape "$4")
stderr_log=$(xml_escape "$5")

cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.wedecent.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$agent</string>
    <string>serve</string>
    <string>--config=$config</string>
    <string>--state=$state</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>Umask</key>
  <integer>63</integer>
  <key>StandardOutPath</key>
  <string>$stdout_log</string>
  <key>StandardErrorPath</key>
  <string>$stderr_log</string>
</dict>
</plist>
EOF
