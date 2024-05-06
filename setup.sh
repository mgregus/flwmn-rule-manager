#!/bin/bash


echo "#!/bin/bash" > rule-manager
echo "$(which python3) $(pwd)/manager/rule-manager.py \"\$@\"" >> rule-manager

chmod +x rule-manager

cp rule-manager /usr/local/bin/