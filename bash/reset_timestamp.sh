#!/bin/bash

# ==========================================
# IMPORT GLOBAL VARS
# ==========================================

# Déchiffrer et charger les variables
eval "$(gpg --batch --passphrase-file ../.gpg_passphrase --quiet --decrypt ../.env.gpg 2>/dev/null | grep -E '^[A-Z_]+=.*' | sed 's/^/export /')"

# ==========================================
# EXECUTE RESET_TIMESTAMP FUNCTION
# ==========================================
python3 -c "
import sys
sys.path.insert(0, '/opt/pphook')
from hook import reset_last_check
reset_last_check()
print('Timestamp reset')
"
