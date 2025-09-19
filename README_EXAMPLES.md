## Example workflow (local)

# 1. Encrypt a file
python -m ztefv.encrypt --in sample.txt --out sample.ztef
# Enter passphrase when prompted.

# 2. View the encrypted file
python -m ztefv.viewer sample.ztef
# Enter the same passphrase when prompted.
