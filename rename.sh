ag --ignore rename.sh -l "event-rule-uprobe-internal\.h" | xargs sed -i 's/event-rule-uprobe-internal\.h/uprobe-internal.h/g'
ag --ignore rename.sh -l "event-rule-kprobe-internal\.h" | xargs sed -i 's/event-rule-kprobe-internal\.h/kprobe-internal.h/g'
ag --ignore rename.sh -l "event-rule-kretprobe-internal\.h" | xargs sed -i 's/event-rule-kretprobe-internal\.h/kretprobe-internal.h/g'
ag --ignore rename.sh -l "event-rule-syscall-internal\.h" | xargs sed -i 's/event-rule-syscall-internal\.h/syscall-internal.h/g'
ag --ignore rename.sh -l "event-rule-tracepoint-internal\.h" | xargs sed -i 's/event-rule-tracepoint-internal\.h/tracepoint-internal.h/g'

ag --ignore rename.sh -l "event-rule-uprobe\.h" | xargs sed -i 's/event-rule-uprobe\.h/uprobe.h/g'
ag --ignore rename.sh -l "event-rule-kprobe\.h" | xargs sed -i 's/event-rule-kprobe\.h/kprobe.h/g'
ag --ignore rename.sh -l "event-rule-kretprobe\.h" | xargs sed -i 's/event-rule-kretprobe\.h/kretprobe.h/g'
ag --ignore rename.sh -l "event-rule-syscall\.h" | xargs sed -i 's/event-rule-syscall\.h/syscall.h/g'
ag --ignore rename.sh -l "event-rule-tracepoint\.h" | xargs sed -i 's/event-rule-tracepoint\.h/tracepoint.h/g'
git add .
git commit --amend --no-edit
